# Stake.com Security Assessment — CORS & GraphQL Schema Leakage

## Live Demo

**Deployed PoC:** [https://bhupenderkumar.github.io/stake-security-poc/](https://bhupenderkumar.github.io/stake-security-poc/)

> ⚠️ **For authorized security research only.** Do NOT use against production systems you do not own or do not have written permission to test.

---

## Repo

- Source: `https://github.com/bhupenderkumar/stake-security-poc`
- Full findings: [`FULL-FINDINGS.md`](FULL-FINDINGS.md)
- PoC HTML: [`cors-poc.html`](cors-poc.html), [`index.html`](index.html)

---

## Summary

Independent security assessment of `https://stake.com/_api/graphql` that identified 10 findings, including 4 Critical and 3 High severity issues. The core issue is a **CORS misconfiguration** that behaves like an open cross-origin proxy: an attacker-controlled site can enumerate GraphQL fields, steal visitor IPs, and, when a session token is present, exfiltrate PII and wallet data.

Key issues demonstrated:
1. **CORS wildcard origin with credentials enabled.**
2. **Cross-origin IP theft — no authentication required.**
3. **User enumeration — 20/20 platform accounts resolved.**
4. **Full authenticated data extraction (PII, wallets, sessions) via `x-access-token`.**
5. **Schema reconstructed without introspection due to verbose error messages.**
6. **Admin mutations exposed and callable from arbitrary origins when an origin has a valid token.**

This repo captures the validated PoC, the workflow-based auto-deploy via GitHub Pages, and the consolidated findings.

---

## Verification

- Target API: `https://stake.com/_api/graphql`
- Assessment date: **May 22, 2026**
- Researcher: **Bhupender Kumar**
