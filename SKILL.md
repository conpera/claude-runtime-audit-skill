---
name: claude-runtime-audit
description: >-
  Use when auditing whether a Linux or native Windows 10+ workstation, VM,
  container, cloud desktop, or remote host is suitable for Claude Code engineering
  work. Triggers include Claude Code runtime readiness checks without requiring WSL,
  account-risk or ban-risk triage, US-region workstation consistency,
  Docker/VM/TUN/proxy fingerprints, locale/timezone/font traces, China or non-US
  residue, Node/Claude CLI/network availability, and comparison of local Docker,
  local VM, VPS, native Windows, or cloud desktop profiles before running Claude Code.
---

# Claude Runtime Audit

## Purpose

Run a disciplined, read-only audit of a target Linux or native Windows environment before trusting it as a Claude Code runtime. Separate two questions: whether Claude Code can run reliably, and whether the environment truthfully matches the requested profile, such as a US-region workstation.

Do not use this skill to hide, forge, or remove environment fingerprints. If the requested outcome is “a judge cannot tell this is a VM/container/proxy,” report the visible facts and recommend using a real matching environment, such as a US-hosted VM/cloud desktop/bare-metal host, rather than spoofing runtime facts.

## Quick workflow

1. Copy or reference `scripts/claude_runtime_audit.py` on the target machine.
2. Install Python 3.9+ on the target. On native Windows, use Windows PowerShell 5.1+ or PowerShell 7; do not require WSL.
3. Run the script from the target Linux shell, Windows PowerShell, or CMD so routes, interface IPs, proxy settings, locale, timezone, DNS, HOME, and platform-specific virtualization facts reflect what Claude Code sees.
4. For a normal Linux readiness check, run:

```bash
python3 /path/to/claude_runtime_audit.py --target-country US --scan-known-home
```

5. For the same check on native Windows PowerShell, run:

```powershell
py -3 .\scripts\claude_runtime_audit.py `
  --target-country US `
  --scan-known-home
```

If the Windows Python launcher is unavailable, replace `py -3` with `python`.

6. For a strict “US workstation consistency” check on Linux, run:

```bash
python3 /path/to/claude_runtime_audit.py \
  --target-country US \
  --target-timezone America/Los_Angeles \
  --strict-us-workstation \
  --scan-known-home
```

7. On Windows, use the same flags and pass either an IANA timezone such as `America/Los_Angeles` or a Windows timezone ID such as `Pacific Standard Time`.
8. Treat `FAIL` as blockers, `WARN` as evidence to disclose or fix legitimately, and `INFO` as context. Do not interpret absence of one fingerprint as proof of a physical or compliant machine.

## Interpreting results

Claude Code runtime readiness mainly depends on a supported Linux or 64-bit Windows userland, working HTTPS, a usable shell, enough disk space, and stable filesystem/network behavior. Treat Node/npm as optional when using Claude Code's native installer; require them only for the npm installation method or project workflows that need them. On native Windows, prefer Git for Windows for complete Bash and Git workflow support, while auditing the actual PowerShell/CMD runtime when Git Bash is absent.

Profile consistency is stricter. A local Docker container can be a good dev runtime but will expose Docker facts such as `/.dockerenv`, overlay filesystems, cgroups, container hostnames, or proxy env vars. A local Lima/UTM/Parallels/VMware VM can remove Docker facts but may expose hypervisor facts, guest agents, TUN devices, or proxy processes. If the profile requires “looks like a real US computer,” the legitimate solution is to run on an actual US-based host or cloud desktop and audit it there.

Read `references/audit-policy.md` when scoring policy, redaction expectations, or a manual follow-up checklist are needed.

## Bundled script

`scripts/claude_runtime_audit.py` is a dependency-free Python 3.9+ script. It selects Linux or native Windows collectors automatically and keeps one shared JSON/Markdown report format. It performs read-only checks for:

- OS, architecture, filesystem, container, and virtualization evidence from Linux `/proc`/DMI or Windows CIM/BIOS.
- Locale, timezone, enabled Chinese locales/languages, and CJK font hints from Linux tools or native Windows APIs/registry.
- Local interface IPv4/IPv6 addresses, routes, proxy environment variables, Windows user/WinHTTP proxy settings, TUN/WireGuard/VPN/proxy interfaces and processes, DNS, and external egress country.
- Default, no-proxy, IPv4-only, and IPv6-only egress checks to catch proxy-route differences or IPv6 leaks.
- Node/npm/git/curl/Claude CLI availability, including safe invocation of Windows `.cmd`/`.bat` shims, and basic HTTPS reachability.
- Optional privacy-preserving HOME scan of known config/history locations, including PowerShell history and `%APPDATA%`, for CJK text, China-region strings, proxy variables, and Claude/Codex session residue.

The script redacts common credentials from proxy URLs and process arguments, and it reports matched file paths/counts rather than printing private history content.

## Known limitations

This skill is a runtime/profile audit, not a guarantee that an account will be safe or accepted by any provider. It does not test browser fingerprinting, WebRTC, TLS/JA3 reputation, paid IP reputation databases, Claude account status, billing status, CAPTCHA behavior, or provider-side risk scoring. Treat the output as evidence for engineering triage and environment selection, not as an evasion recipe or a complete account-risk certification.
