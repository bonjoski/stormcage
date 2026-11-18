# Stormcage Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, prompt firewall invariants, and cross-agent context isolation models governing [`bonjoski/stormcage`](https://github.com/bonjoski/stormcage).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-cross-agent-context-memory-firewall.md)** | **Cross-Agent Context & Cognitive Memory Firewall (OWASP LLM01)** | `Accepted` | 2026-10-30 | `pkg/firewall`, `pkg/sanitizer` |

---

## Architectural Principles

1. **In-Process Go Library:** Embedded directly into developer agent test harnesses and memory pipelines with 0ms network hop tax; never deployed as an inline network AI firewall.
2. **Strict Delimiter Quarantine:** Encapsulates untrusted inputs inside strict `<untrusted_content>` fences.
3. **Deterministic Prompt Injection Filtering:** Uses heuristic classifiers and regex pattern matchers to detect jailbreaks and prompt override vectors before memory insertion.
