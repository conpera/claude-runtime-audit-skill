---
name: claude-runtime-audit
description: >-
  Use when auditing whether a Linux, VM, container, cloud desktop, or remote host
  is suitable for Claude Code engineering work. Triggers include Claude Code runtime
  readiness checks, account-risk or ban-risk triage, US-region workstation
  consistency, Docker/VM/TUN/proxy fingerprints, locale/timezone/font traces,
  China or non-US residue, Node/Claude CLI/network availability, and comparison
  of local Docker, local VM, VPS, or cloud desktop profiles before running
  Claude Code.
---

# Claude Runtime Audit

## Purpose

Use this skill to run a disciplined, read-only audit of a target Linux environment before trusting it as a Claude Code runtime. The audit separates two questions: whether Claude Code can run reliably, and whether the environment truthfully matches the requested profile, such as a US-region workstation.

Do not use this skill to hide, forge, or remove environment fingerprints. If the requested outcome is “a judge cannot tell this is a VM/container/proxy,” report the visible facts and recommend using a real matching environment, such as a US-hosted VM/cloud desktop/bare-metal host, rather than spoofing runtime facts.

## Quick workflow

1. Copy or reference `scripts/claude_runtime_audit.py` on the target machine.
2. Run it from inside the target terminal, not from the host, so PID 1, cgroups, routes, interface IPs, proxy variables, locale, timezone, DNS, and HOME reflect what Claude Code would see.
3. For a normal readiness check, run:

```bash
python3 /path/to/claude_runtime_audit.py --target-country US --scan-known-home
```

4. For a strict “US workstation consistency” check, run:

```bash
python3 /path/to/claude_runtime_audit.py \
  --target-country US \
  --target-timezone America/Los_Angeles \
  --strict-us-workstation \
  --scan-known-home
```

5. Treat `FAIL` as blockers, `WARN` as evidence to disclose or fix legitimately, and `INFO` as context. Do not interpret absence of one fingerprint as proof of a physical or compliant machine.

## Interpreting results

Claude Code runtime readiness mainly depends on a healthy Linux userland, working HTTPS, modern Node/npm if Claude Code must be installed, a usable shell, and stable filesystem/network behavior.

Profile consistency is stricter. A local Docker container can be a good dev runtime but will expose Docker facts such as `/.dockerenv`, overlay filesystems, cgroups, container hostnames, or proxy env vars. A local Lima/UTM/Parallels/VMware VM can remove Docker facts but may expose hypervisor facts, guest agents, TUN devices, or proxy processes. If the profile requires “looks like a real US computer,” the legitimate solution is to run on an actual US-based host or cloud desktop and audit it there.

Read `references/audit-policy.md` when scoring policy, redaction expectations, or a manual follow-up checklist are needed.

## Bundled script

`scripts/claude_runtime_audit.py` is a dependency-free Python 3 script. It performs read-only checks for:

- OS, kernel, PID 1, filesystem, container, cgroup, and virtualization evidence.
- Locale, timezone, enabled Chinese locales, and CJK font hints.
- Local interface IPv4/IPv6 addresses, proxy environment variables, TUN/WireGuard/VPN/proxy interfaces and processes, DNS, and external egress country.
- Default, no-proxy, IPv4-only, and IPv6-only egress checks to catch proxy-route differences or IPv6 leaks.
- Node/npm/git/curl/Claude CLI availability and basic HTTPS reachability.
- Optional privacy-preserving HOME scan of known config/history locations for CJK text, China-region strings, proxy variables, and Claude/Codex session residue.

The script redacts common credentials from proxy URLs and process arguments, and it reports matched file paths/counts rather than printing private history content.

## Known limitations

This skill is a runtime/profile audit, not a guarantee that an account will be safe or accepted by any provider. It does not test browser fingerprinting, WebRTC, TLS/JA3 reputation, paid IP reputation databases, Claude account status, billing status, CAPTCHA behavior, or provider-side risk scoring. Treat the output as evidence for engineering triage and environment selection, not as an evasion recipe or a complete account-risk certification.
