#!/usr/bin/env python3
"""
Horus - Secure Microkernel Assistant

A small, predictable REPL over the Claude API: one model, one system prompt,
robust output handling. Change MODEL / MAX_TOKENS below if you want to.
"""

import os
import sys
import json
from datetime import datetime

from anthropic import Anthropic

# ============================ CONFIG ============================
# One fixed model, so behaviour and cost are predictable. Opus 4.8 is the most
# capable model and the right default for security-critical kernel work.
# Swap to "claude-sonnet-4-6" if you want ~40% lower cost.
MODEL      = "claude-opus-4-8"
MAX_TOKENS = 8192

SYSTEM_PROMPT_FILE = "system_prompt.txt"
LOG_FILE           = "horus_usage.log"

# USD per 1M tokens, for the cost read-out only. Keep in sync with MODEL.
PRICE = {
    "claude-opus-4-8":   {"in": 5.0, "out": 25.0},
    "claude-sonnet-4-6": {"in": 3.0, "out": 15.0},
}
# ================================================================


def load_system_prompt() -> str:
    try:
        with open(SYSTEM_PROMPT_FILE, "r", encoding="utf-8") as f:
            text = f.read().strip()
    except OSError as e:
        sys.exit(f"[X] Could not read {SYSTEM_PROMPT_FILE}: {e}")
    if not text:
        sys.exit(f"[X] {SYSTEM_PROMPT_FILE} is empty.")
    return text


def extract_text(message) -> str:
    """Return the assistant's text regardless of what block types came back."""
    if getattr(message, "stop_reason", None) == "refusal":
        return "[The model declined to answer this request.]"
    parts = [b.text for b in message.content if getattr(b, "type", None) == "text"]
    return "\n".join(parts).strip() or "[No text in the response.]"


def estimate_cost(usage) -> float:
    p = PRICE.get(MODEL)
    if not p:
        return 0.0
    return (usage.input_tokens * p["in"] + usage.output_tokens * p["out"]) / 1_000_000


def log_usage(usage, cost: float) -> None:
    # Best-effort: logging must never break the chat.
    try:
        with open(LOG_FILE, "a") as f:
            json.dump({
                "ts": datetime.now().isoformat(),
                "model": MODEL,
                "in": usage.input_tokens,
                "out": usage.output_tokens,
                "cost": round(cost, 6),
            }, f)
            f.write("\n")
    except OSError:
        pass


def main() -> None:
    if not os.getenv("ANTHROPIC_API_KEY"):
        sys.exit("[X] Set ANTHROPIC_API_KEY first.")

    client = Anthropic()  # the SDK auto-retries transient errors (429 / 5xx / network)
    # cache_control is harmless: it does nothing while the prompt is short, and
    # automatically saves cost if the prompt ever grows past the cache minimum.
    system = [{
        "type": "text",
        "text": load_system_prompt(),
        "cache_control": {"type": "ephemeral"},
    }]

    messages: list[dict] = []
    total_cost = 0.0

    print("=== Horus - Secure Microkernel Assistant ===")
    print(f"Model: {MODEL}  |  Commands: 'new' (reset), 'exit'\n")

    while True:
        try:
            user_input = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break

        if not user_input:
            continue
        if user_input.lower() in ("exit", "quit", "q"):
            print("Bye.")
            break
        if user_input.lower() in ("new", "reset", "/new"):
            messages = []
            print("Conversation reset.\n")
            continue

        messages.append({"role": "user", "content": user_input})

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=system,
                messages=messages,
            )
        except Exception as e:
            # Keep the REPL alive; drop the unanswered turn so history stays valid.
            print(f"[X] Request failed: {e}\n")
            messages.pop()
            continue

        reply = extract_text(response)
        print(f"\nHorus:\n{reply}\n")
        messages.append({"role": "assistant", "content": reply})

        cost = estimate_cost(response.usage)
        total_cost += cost
        print(f"[in {response.usage.input_tokens} / out {response.usage.output_tokens}"
              f" | ${cost:.4f} this | ${total_cost:.4f} total]\n")
        log_usage(response.usage, cost)


if __name__ == "__main__":
    main()
