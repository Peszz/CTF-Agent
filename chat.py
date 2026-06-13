#!/usr/bin/env python3
"""
Interactive chat mode — talk to the CTF agent live.
Instead of running autonomously, you guide it step by step.

Usage: python3 chat.py

This reuses CTFAgent's tool dispatcher and TOOLS list directly, so it always
stays in sync with the autonomous agent (terminal tools, web_search, etc.).
"""

import json
import requests

try:
    import readline  # enables arrow-key history (not present on Windows by default)
except ImportError:
    pass

from config import Config
from agent import CTFAgent, TOOLS, normalize_llm_message
from notes import Notes


def run_interactive():
    cfg = Config()
    # Build a normal agent — gives us the SSH/terminal connection, the logger,
    # the system prompt, and crucially the SAME _dispatch_tool used autonomously.
    agent = CTFAgent(cfg)
    agent.logger.log_file = "chat_session_log.json"

    agent.kali.connect()
    agent.notes = Notes(agent.kali.client, target="interactive")

    print("\n" + "=" * 60)
    print("  Kali CTF Agent — Interactive Mode")
    print("  Type your instructions. 'exit' to quit.")
    print("=" * 60 + "\n")

    while True:
        try:
            user_input = input("You > ").strip()
        except (EOFError, KeyboardInterrupt):
            break

        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue

        agent.messages.append({"role": "user", "content": user_input})

        # Agentic loop for this turn (the model may chain several tool calls)
        while True:
            payload = {
                "model": cfg.model,
                "messages": agent.messages,
                "tools": TOOLS,
                "tool_choice": "auto",
                "parallel_tool_calls": False,   # see normalize_llm_message — Gemma dup-call guard
                "temperature": cfg.temperature,
                "top_p": cfg.top_p,
                "top_k": cfg.top_k,
                "max_tokens": cfg.max_tokens,
            }
            try:
                resp = requests.post(
                    f"{cfg.lm_studio_url}/v1/chat/completions",
                    json=payload,
                    timeout=300,
                )
                resp.raise_for_status()
                data = resp.json()
            except requests.exceptions.ConnectionError:
                print(f"\n[error] Cannot reach LM Studio at {cfg.lm_studio_url} — is it running?")
                break
            except requests.exceptions.Timeout:
                print("\n[error] LM Studio request timed out after 300s.")
                break
            except requests.exceptions.HTTPError as e:
                print(f"\n[error] LM Studio returned {e.response.status_code}: {e.response.text[:300]}")
                break

            message = normalize_llm_message(data["choices"][0]["message"])
            agent.messages.append(message)
            agent.logger.log_llm_message(message)

            if message.get("content"):
                print(f"\nAgent > {message['content']}\n")

            # Dispatch whenever there are tool calls, regardless of finish_reason: when
            # normalize_llm_message recovers Gemma native-format calls from content, the model
            # reported finish_reason="stop" but we DO have calls to run.
            if not message.get("tool_calls"):
                break

            # Delegate ALL tool handling to the agent's dispatcher — single
            # source of truth, so chat mode supports every tool the agent does.
            for tc in message.get("tool_calls", []):
                fn_name = tc["function"]["name"]
                fn_args = json.loads(tc["function"]["arguments"])

                result_str = agent._dispatch_tool(fn_name, fn_args)

                agent.messages.append({
                    "role": "tool",
                    "tool_call_id": tc["id"],
                    "content": result_str,
                })

                if agent.finished:
                    break

            if agent.finished:
                break

    agent.kali.disconnect()
    agent.logger.save()
    print("\n[+] Session saved. Bye!")


if __name__ == "__main__":
    run_interactive()
