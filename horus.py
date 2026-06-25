#!/usr/bin/env python3
"""
Horus - Secure Microkernel Assistant (Fixed v2)
"""

import os
import sys
import json
from datetime import datetime
from anthropic import Anthropic

# ====================== CONFIG ======================
DEFAULT_MODEL = "claude-sonnet-4-6"
OPUS_MODEL    = "claude-opus-4-8"

PRICING = {
    "claude-sonnet-4-6": {"input": 3.0,  "output": 15.0},
    "claude-opus-4-8":   {"input": 5.0,  "output": 25.0},
}

OPUS_KEYWORDS = [
    "security", "vulnerability", "attack", "exploit", "TCB", "capability",
    "least privilege", "formal", "verification", "invariant", "architecture",
    "design decision", "critical", "boot", "IPC", "unsafe", "revoke", "lineage",
    "TOCTOU", "use-after-revoke", "race"
]

LOG_FILE = "horus_usage.log"
SYSTEM_PROMPT_FILE = "system_prompt.txt"
# ====================================================


def load_system_prompt():
    try:
        with open(SYSTEM_PROMPT_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"❌ {SYSTEM_PROMPT_FILE} not found!")
        sys.exit(1)


def should_use_opus(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in OPUS_KEYWORDS)


def estimate_cost(model: str, input_t: int, output_t: int, cache_read: int = 0) -> float:
    p = PRICING.get(model, PRICING[DEFAULT_MODEL])
    effective_input = max(0, input_t - cache_read)
    cost = (effective_input * p["input"] + output_t * p["output"]) / 1_000_000
    return round(cost, 6)


def main():
    print("=== Horus - Secure Microkernel Assistant (Fixed v2) ===")
    print(f"Default: {DEFAULT_MODEL} | Auto-escalates to Opus on critical topics")
    print("Prompt caching enabled | Usage logged to horus_usage.log\n")

    if not os.getenv("ANTHROPIC_API_KEY"):
        print("❌ Set ANTHROPIC_API_KEY first")
        sys.exit(1)

    client = Anthropic()
    system_prompt = load_system_prompt()
    messages = []
    cumulative_cost = 0.0

    while True:
        try:
            user_input = input("You: ").strip()
            if user_input.lower() in ["exit", "quit", "q"]:
                print("👋 Goodbye!")
                break
            if not user_input:
                continue   # skip empty input

            use_opus = should_use_opus(user_input)
            model = OPUS_MODEL if use_opus else DEFAULT_MODEL

            if use_opus:
                print(f"🔒 Escalating to {OPUS_MODEL}...")

            messages.append({"role": "user", "content": user_input})

            # === SYSTEM + CACHING (no temperature) ===
            response = client.messages.create(
                model=model,
                max_tokens=8192,
                system=[
                    {
                        "type": "text",
                        "text": system_prompt,
                        "cache_control": {"type": "ephemeral"}
                    }
                ],
                messages=messages,
                extra_headers={
                    "anthropic-beta": "prompt-caching-2024-07-31"
                }
            )

            assistant_reply = response.content[0].text
            print(f"\nHorus ({model.split('-')[-1]}):\n{assistant_reply}\n")

            # Usage stats
            usage = response.usage
            input_tokens = usage.input_tokens
            output_tokens = usage.output_tokens
            cache_read = getattr(usage, "cache_read_input_tokens", 0)
            cache_write = getattr(usage, "cache_creation_input_tokens", 0)

            cost = estimate_cost(model, input_tokens, output_tokens, cache_read)
            cumulative_cost += cost

            print(f"[Usage] {model} | In: {input_tokens} (cached:{cache_read}) | "
                  f"Out: {output_tokens} | This: ${cost:.5f} | Total: ${cumulative_cost:.4f}\n")

            # Log to file
            with open(LOG_FILE, "a") as f:
                json.dump({
                    "ts": datetime.now().isoformat(),
                    "model": model,
                    "input": input_tokens,
                    "output": output_tokens,
                    "cache_read": cache_read,
                    "cost": cost,
                    "cumulative": cumulative_cost
                }, f)
                f.write("\n")

            messages.append({"role": "assistant", "content": assistant_reply})

            if len(messages) > 30:
                print("💡 Tip: Conversation is long — type '/new' to start fresh (saves tokens).\n")

        except KeyboardInterrupt:
            print("\n👋 Interrupted. Goodbye!")
            break
        except Exception as e:
            print(f"❌ Error: {e}")
            # Remove the last user message so it doesn't retry the same bad input
            if messages and messages[-1]["role"] == "user":
                messages.pop()


if __name__ == "__main__":
    main()
