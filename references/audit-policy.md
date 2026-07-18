# Claude Runtime Audit Policy

## Boundaries

The audit is for readiness and truthfulness, not evasion. Do not provide steps to spoof DMI, hide guest agents, mask TUN devices, alter audit tools, forge geolocation, or make a local/proxied system indistinguishable from a real US machine. If a strict profile cannot be satisfied locally, recommend a real US-hosted environment and run the same audit there.

## Severity model

- `FAIL`: likely blocker for the requested target profile or Claude Code operation.
- `WARN`: visible counterevidence, drift, or configuration that can confuse Claude Code or future audits.
- `PASS`: expected condition verified.
- `INFO`: context; not inherently good or bad.

## Runtime readiness checks

Minimum practical readiness includes a supported Linux userland, working shell, HTTPS egress, enough disk in HOME, and Node/npm when Claude Code installation or update is needed. If Claude Code is already installed, still verify `claude --version` and basic network egress.

## Profile consistency checks

For a US workstation-like profile, expect:

- External egress country is US in both default curl and `--noproxy '*'` tests, unless the design explicitly uses env proxy.
- IPv4-only and IPv6-only egress do not diverge from the target country. IPv6 being unavailable is not itself a failure, but IPv6 silently exiting a different country is a profile-risk signal.
- Local interface IPv4/IPv6 addresses, default route, policy routes, and DNS resolvers are consistent with the intended runtime design.
- Timezone and locale are intentionally configured, typically a US timezone such as `America/Los_Angeles` or `America/New_York` and `en_US.UTF-8` for North-America-like defaults, or another explicitly requested setting.
- No enabled `zh_CN`, `zh_TW`, or other unexpected locale residue unless intentionally installed.
- No Docker/container fingerprints if the target is supposed to be a VM or physical/cloud workstation.
- No local-hypervisor, guest-agent, visible TUN, or proxy-process evidence if the target is supposed to be a physical/native US machine. If these appear, disclose them rather than trying to hide them.

## Recommended next step by environment class

- Docker: acceptable for reproducible dev tasks, not for strict workstation identity.
- Local VM: acceptable for stronger isolation and system-level TUN testing, not for proving a US physical/native machine.
- US VPS/cloud desktop: best practical default for a true US-region remote Linux runtime.
- US bare metal/Mac cloud: strongest option when virtualization or data-center fingerprints themselves matter.

## Out of scope

This audit does not certify account safety. Browser/WebRTC fingerprints, TLS/JA3 reputation, provider-specific account status, payment/billing trust, CAPTCHA flows, behavioral history, and paid IP reputation feeds require separate checks. Do not present a clean audit as proof that a Claude account cannot be restricted.
