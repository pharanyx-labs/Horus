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
# One fixed model, so behaviour and cost are predictable. Opus 5 is the current
# Opus and the right default for security-critical kernel work, at the same
# $5/$25 per MTok Opus 4.8 cost -- so this is a capability change and not a
# price one. Swap to "claude-sonnet-5" ($2/$10) if you want the cheaper tier.
#
# THINKING IS NOT CONFIGURED HERE, AND THAT IS THE CORRECT CALL RATHER THAN AN
# OMISSION. On Opus 5 thinking is on by default: omitting the parameter runs
# adaptive thinking, which is what this tool wants. Setting it explicitly buys
# nothing, and `{"type": "disabled"}` would cost something real -- with thinking
# off the model occasionally writes what should be a tool call, or a <thinking>
# tag, into the visible text. The old `budget_tokens` form is rejected outright
# on this model.
MODEL      = "claude-opus-5"
MAX_TOKENS = 8192

# Both live at the REPOSITORY ROOT, resolved from this file's location rather
# than from the working directory: the script moved under tools/ (roadmap 4.6,
# audit finding M-2), and a bare relative name would then mean "wherever the
# operator happened to be standing" -- which for the prompt is a silent change of
# what the assistant is told, and for the log is a second log nobody reads.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_PROMPT_FILE = os.path.join(_ROOT, "system_prompt.txt")
LOG_FILE           = os.path.join(_ROOT, "horus_usage.log")

# USD per 1M tokens, for the cost read-out only. Keep in sync with MODEL: an
# entry that is missing makes estimate_cost() return 0.0 rather than guess, which
# is the safe direction -- a silent zero in the log is better than a number
# derived from the wrong tier.
PRICE = {
    "claude-opus-5":     {"in": 5.0, "out": 25.0},
    "claude-sonnet-5":   {"in": 2.0, "out": 10.0},
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
