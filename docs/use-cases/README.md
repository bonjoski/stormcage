# 💡 Stormcage End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/stormcage`](https://github.com/bonjoski/stormcage)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Stormcage** is an in-memory context firewall and semantic taint-tracking engine for autonomous multi-agent systems. It isolates untrusted third-party inputs, strips invisible Unicode evasion tricks, and prevents indirect prompt injection from contaminating privileged coordinator agents.

This directory provides task-oriented recipes for common agent memory protection workflows.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Mechanism |
| :--- | :--- | :--- | :--- |
| **[01. Cross-Agent Context Taint Scanning](01-context-taint-scanning.md)** | Scan untrusted text (web scrape outputs, issues, PR comments) for prompt injection before ingesting. | `stormcage scan <file>` | Semantic Taint Analyzer |
| **[02. Unicode Normalization & Invisible Stripping](02-unicode-normalization.md)** | Strip zero-width characters, bidirectional overrides, and homoglyphs from agent context. | `stormcage sanitize <input>` | NFKC Unicode Sanitizer |
| **[03. Compartmentalized Memory Firewall Daemon](03-memory-firewall-daemon.md)** | Run background daemon to enforce strict memory partitions between untrusted subagents and coordinator. | `stormcage daemon start` | IPC Memory Firewall |
