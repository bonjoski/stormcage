# ADR-0001: Cross-Agent Context & Cognitive Memory Firewall (OWASP LLM01)

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/firewall`, `pkg/sanitizer`
- **Deciders:** Lead Cognitive Security Architect & AI Safety Engineer

---

## 1. Context & Problem Statement

In multi-agent swarms, agents share memory ledgers, vector stores, and conversational contexts.
- An untrusted input processed by Agent A (e.g. an external issue comment or scraped web page) can contain an embedded prompt injection ("Ignore all previous instructions...").
- When Agent A commits this tainted text into shared memory, Agent B reads it and executes malicious instructions with elevated privileges (Privilege Escalation via Memory Poisoning).

---

## 2. Decision Outcome

We built **Stormcage**, an in-process cognitive memory firewall:

1. **Two-Tiered Fast-Path Inspection:**
   - Tier 1: Microsecond regex pre-filter (< 1ms) detecting delimiter breakout sequences (`</context>`, `System:`, `Human:`).
   - Tier 2: Heuristic structural classifier (< 10ms) scanning for directive-overriding grammar.
2. **Context Isolation & Delimiter Fencing:**
   - Wraps all external artifacts in immutable XML boundaries with random session nonces.
3. **Poisoned Memory Quarantine:**
   - Blocks tainted text blocks from entering semantic vector stores without terminating peer subagents.

---

## 3. Consequences

- **Positive:** Neutralizes OWASP LLM01 prompt injection attacks across multi-agent memory channels.
- **Negative:** Highly sophisticated, novel multi-turn semantic jailbreaks may require continuous rule pack updates.
