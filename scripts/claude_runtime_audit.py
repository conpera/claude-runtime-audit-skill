#!/usr/bin/env python3
"""Read-only Claude Code runtime/profile audit for Linux environments."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, Optional

SECRET_RE = re.compile(r"(?i)(token|password|passwd|secret|key|authorization|bearer)=([^\s&]+)")
URL_CRED_RE = re.compile(r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)(?P<cred>[^/@\s]+@)")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")
CN_HINT_RE = re.compile(r"(?i)\b(cn|china|mainland|zh_CN|Asia/Shanghai|Shanghai|Beijing|Guangzhou|Shenzhen)\b")
PROXY_ENV_NAMES = [
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
]
VPN_PROC_RE = re.compile(
    r"(?i)\b(sing-box|clash|mihomo|v2ray|xray|hysteria|wireguard|wg-quick|tailscaled|zerotier|openvpn|netlink|agentlink|gost|trojan|ss-local|shadowsocks|privoxy|mitmproxy|squid)\b"
)
TUN_IFACE_RE = re.compile(r"(?i)\b(tun\d*|tap\d*|utun\d*|wg\d*|tailscale\d*|zt\w*|ppp\d*|cni\d*|docker\d*|veth\w*)\b")
CHINA_DNS = {"114.114.114.114", "223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29"}


@dataclass
class Check:
    id: str
    status: str
    severity: str
    title: str
    evidence: str = ""
    recommendation: str = ""


class Auditor:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.checks: list[Check] = []
        self.facts: dict[str, object] = {}

    def add(self, id_: str, status: str, severity: str, title: str, evidence: object = "", recommendation: str = "") -> None:
        if isinstance(evidence, (dict, list, tuple)):
            ev = json.dumps(evidence, ensure_ascii=False, indent=2)
        else:
            ev = str(evidence).strip()
        self.checks.append(Check(id_, status, severity, title, ev, recommendation))

    def run(self, cmd: list[str], timeout: int = 6, env: Optional[dict[str, str]] = None) -> tuple[int, str, str]:
        try:
            p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except FileNotFoundError:
            return 127, "", f"command not found: {cmd[0]}"
        except subprocess.TimeoutExpired as e:
            return 124, (e.stdout or "").strip() if isinstance(e.stdout, str) else "", "timeout"
        except Exception as e:  # defensive: audit must not crash
            return 1, "", repr(e)

    def read(self, path: str, limit: int = 12000) -> str:
        try:
            return Path(path).read_text(errors="replace")[:limit]
        except Exception:
            return ""

    def redact(self, s: str) -> str:
        s = URL_CRED_RE.sub(lambda m: m.group("scheme") + "<redacted>@", s)
        s = SECRET_RE.sub(lambda m: f"{m.group(1)}=<redacted>", s)
        s = re.sub(r"(?i)(authorization:?)\s+\S+", r"\1 <redacted>", s)
        return s

    def ip_kind(self, cidr: str) -> str:
        try:
            ip = ipaddress.ip_interface(cidr).ip
        except ValueError:
            return "unknown"
        flags = []
        if ip.is_private:
            flags.append("private")
        if ip.is_global:
            flags.append("global")
        if ip.is_link_local:
            flags.append("link-local")
        if ip.is_loopback:
            flags.append("loopback")
        if ip.is_multicast:
            flags.append("multicast")
        return ",".join(flags) or "special"

    def headline(self) -> tuple[str, str]:
        fail = sum(1 for c in self.checks if c.status == "FAIL")
        warn = sum(1 for c in self.checks if c.status == "WARN")
        runtime_fail = [c for c in self.checks if c.status == "FAIL" and c.severity == "runtime"]
        if runtime_fail:
            return "NOT READY", f"{len(runtime_fail)} runtime blocker(s), {fail} total fail(s), {warn} warning(s)."
        if fail:
            return "CONDITIONAL", f"Runtime may work, but target profile has {fail} fail(s) and {warn} warning(s)."
        if warn:
            return "CONDITIONAL", f"No hard blocker found, but {warn} warning(s) need review."
        return "READY", "No fails or warnings from this audit."

    def audit_platform(self) -> None:
        self.facts["python"] = sys.version.split()[0]
        self.facts["platform"] = platform.platform()
        self.facts["machine"] = platform.machine()
        self.facts["hostname"] = platform.node()
        os_release = self.read("/etc/os-release")
        pretty = ""
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
        self.facts["os"] = pretty or platform.system()
        code, uname, _ = self.run(["uname", "-a"])
        self.facts["uname"] = uname if code == 0 else platform.platform()
        if platform.system().lower() != "linux":
            self.add("os.linux", "FAIL", "runtime", "Target is not Linux", platform.system(), "Run this audit inside the Linux environment where Claude Code will run.")
        else:
            self.add("os.linux", "PASS", "runtime", "Linux userland detected", self.facts["os"])

        code, pid1, _ = self.run(["sh", "-c", "ps -p 1 -o comm= 2>/dev/null || true"])
        self.facts["pid1"] = pid1
        self.add("os.pid1", "INFO", "profile", "PID 1 process", pid1 or "unknown")

        for tool in ["sh", "bash", "zsh", "git", "curl"]:
            path = shutil.which(tool)
            self.add(f"tool.{tool}", "PASS" if path else "WARN", "runtime", f"{tool} availability", path or "not found", "Install it if Claude Code workflows depend on it." if not path else "")

        for tool in ["node", "npm", "claude"]:
            path = shutil.which(tool)
            if not path:
                sev = "runtime" if tool == "node" else "profile"
                status = "WARN" if tool != "node" else "FAIL"
                self.add(f"tool.{tool}", status, sev, f"{tool} availability", "not found", "Install Node/npm/Claude Code in this target before relying on it.")
                continue
            code, out, err = self.run([tool, "--version"], timeout=5)
            self.add(f"tool.{tool}", "PASS" if code == 0 else "WARN", "runtime", f"{tool} version", self.redact(out or err or path))

        code, df, _ = self.run(["sh", "-c", "df -h \"$HOME\" 2>/dev/null | tail -1"], timeout=5)
        self.add("fs.home_space", "INFO", "runtime", "HOME filesystem space", df or "unknown")

    def audit_container_vm(self) -> None:
        docker_markers = [p for p in ["/.dockerenv", "/run/.containerenv"] if Path(p).exists()]
        cgroup = self.read("/proc/1/cgroup") + "\n" + self.read("/proc/self/cgroup")
        mountinfo = self.read("/proc/self/mountinfo", limit=40000)
        container_hits = []
        if docker_markers:
            container_hits.extend(docker_markers)
        for pat in ["docker", "kubepods", "containerd", "libpod", "podman", "lxc"]:
            if pat in cgroup.lower() or pat in mountinfo.lower():
                container_hits.append(pat)
        if " overlay " in mountinfo or " overlayfs " in mountinfo:
            container_hits.append("overlayfs")
        container_hits = sorted(set(container_hits))
        strict = self.args.strict_us_workstation
        if container_hits:
            self.add("virt.container", "FAIL" if strict else "WARN", "profile", "Container/Docker evidence visible", container_hits, "Use a VM/cloud host for VM profile; use real US host if strict native profile is required.")
        else:
            self.add("virt.container", "PASS", "profile", "No common container marker found")

        code, virt, _ = self.run(["systemd-detect-virt"], timeout=4)
        if code == 0 and virt and virt != "none":
            self.add("virt.systemd", "FAIL" if strict else "WARN", "profile", "Virtualization detected by systemd", virt, "This is legitimate evidence; do not hide it. Use a real matching host if this matters.")
        else:
            self.add("virt.systemd", "PASS" if code == 0 else "INFO", "profile", "systemd-detect-virt result", virt or "none/unknown")

        dmi = {}
        for name in ["sys_vendor", "product_name", "product_version", "board_vendor", "chassis_vendor", "bios_vendor"]:
            value = self.read(f"/sys/class/dmi/id/{name}").strip()
            if value:
                dmi[name] = value
        if dmi:
            vm_words = re.compile(r"(?i)(virtual|vmware|qemu|kvm|parallels|virtualbox|hyper-v|apple virtualization|lima|utm|xen|bochs)")
            vm_dmi = {k: v for k, v in dmi.items() if vm_words.search(v)}
            if vm_dmi:
                self.add("virt.dmi", "FAIL" if strict else "WARN", "profile", "DMI exposes virtualization/vendor evidence", vm_dmi, "Use actual matching hardware/cloud host if DMI identity matters.")
            else:
                self.add("virt.dmi", "INFO", "profile", "DMI identity", dmi)
        else:
            self.add("virt.dmi", "INFO", "profile", "DMI identity unavailable")

        uname = str(self.facts.get("uname", ""))
        if re.search(r"(?i)(linuxkit|moby|docker|microsoft-standard|wsl)", uname):
            self.add("virt.kernel", "WARN", "profile", "Kernel string exposes special runtime", uname)

    def audit_locale_time_fonts(self) -> None:
        code, td, _ = self.run(["timedatectl"], timeout=5)
        timezone = ""
        if code == 0:
            for line in td.splitlines():
                if "Time zone:" in line:
                    timezone = line.split("Time zone:", 1)[1].strip()
        if not timezone:
            timezone = os.environ.get("TZ") or self.read("/etc/timezone").strip()
        target_tz = self.args.target_timezone
        if target_tz and target_tz not in timezone:
            self.add("locale.timezone", "WARN", "profile", "Timezone differs from requested target", timezone or "unknown", f"Set timezone intentionally if {target_tz} is required.")
        elif timezone:
            self.add("locale.timezone", "PASS", "profile", "Timezone", timezone)
        else:
            self.add("locale.timezone", "INFO", "profile", "Timezone unknown")
        if not target_tz and self.args.strict_us_workstation and (self.args.target_country or "").upper() == "US":
            if timezone and re.search(r"^(America|US)/", timezone):
                self.add("locale.timezone_us_profile", "PASS", "profile", "Timezone is compatible with a US target profile", timezone)
            else:
                self.add("locale.timezone_us_profile", "WARN", "profile", "Strict US profile has no explicit US timezone target", timezone or "unknown", "Pass --target-timezone America/<city> to make timezone validation explicit.")
        if td:
            for key in ["System clock synchronized", "NTP service"]:
                for line in td.splitlines():
                    if key in line:
                        status = "WARN" if key == "System clock synchronized" and "no" in line.lower() else "INFO"
                        self.add(f"time.{key.lower().replace(' ', '_')}", status, "runtime", key, line.strip())

        code, loc, _ = self.run(["locale"], timeout=5)
        lang_blob = "\n".join([loc, os.environ.get("LANG", ""), os.environ.get("LC_ALL", ""), os.environ.get("LANGUAGE", "")])
        if "en_US" in lang_blob or "C.UTF-8" in lang_blob:
            self.add("locale.current", "PASS", "profile", "Current locale looks English/neutral", self.redact(lang_blob))
        else:
            self.add("locale.current", "WARN", "profile", "Current locale is not clearly en_US/C.UTF-8", self.redact(lang_blob), "Use a deliberate locale, usually en_US.UTF-8 for North-America-like defaults.")

        code, locale_a, _ = self.run(["locale", "-a"], timeout=5)
        zh_enabled = [x for x in locale_a.splitlines() if re.search(r"(?i)^zh|_CN|_TW|_HK", x)] if code == 0 else []
        locale_gen = self.read("/etc/locale.gen")
        zh_locale_gen = []
        for line in locale_gen.splitlines():
            s = line.strip()
            if s and not s.startswith("#") and re.search(r"(?i)^zh|zh_CN|zh_TW|zh_HK", s):
                zh_locale_gen.append(s)
        if zh_enabled or zh_locale_gen:
            self.add("locale.zh_enabled", "WARN", "profile", "Chinese locales enabled", {"locale_a": zh_enabled, "locale_gen": zh_locale_gen}, "Disable unused locales if they are not intentionally part of the profile.")
        else:
            self.add("locale.zh_enabled", "PASS", "profile", "No enabled Chinese locale found")

        if shutil.which("fc-match"):
            code, sans, _ = self.run(["fc-match", "sans"], timeout=5)
            self.add("font.sans", "INFO", "profile", "Default sans font", sans or "unknown")
        if shutil.which("fc-list"):
            code, fonts, _ = self.run(["fc-list"], timeout=6)
            cjk_hits = []
            for line in fonts.splitlines():
                if re.search(r"(?i)(noto.*cjk|source han|wenquanyi|wqy|simsun|simhei|yahei|pingfang|ar pl|uming|ukai|cjk)", line):
                    cjk_hits.append(line[:220])
                    if len(cjk_hits) >= 10:
                        break
            if cjk_hits:
                self.add("font.cjk", "WARN", "profile", "CJK font hints installed", cjk_hits, "Remove only if the target profile should avoid CJK font residue.")
            else:
                self.add("font.cjk", "PASS", "profile", "No obvious CJK font hints found")

    def audit_network(self) -> None:
        proxy_env = {k: self.redact(v) for k, v in os.environ.items() if k in PROXY_ENV_NAMES and v}
        active_proxy_env = {k: v for k, v in proxy_env.items() if k.lower() != "no_proxy"}
        if active_proxy_env:
            self.add("net.proxy_env", "FAIL" if self.args.strict_us_workstation else "WARN", "profile", "Active proxy environment variables visible", proxy_env, "For global routing, prefer real network design; do not rely on hidden env vars for strict profiles.")
        elif proxy_env:
            self.add("net.proxy_env", "INFO", "profile", "Only NO_PROXY/no_proxy environment variables visible", proxy_env)
        else:
            self.add("net.proxy_env", "PASS", "profile", "No proxy env variables visible")

        if shutil.which("ip"):
            code, links, _ = self.run(["ip", "-o", "link", "show"], timeout=5)
            ifaces = []
            for line in links.splitlines():
                parts = line.split(":", 2)
                if len(parts) >= 2:
                    ifaces.append(parts[1].strip())
            tun_ifaces = [x for x in ifaces if TUN_IFACE_RE.search(x)]
            if tun_ifaces:
                self.add("net.tun_iface", "FAIL" if self.args.strict_us_workstation else "WARN", "profile", "TUN/VPN/container-like interfaces visible", tun_ifaces, "Visible network interfaces are runtime facts; disclose them or use a real target network.")
            else:
                self.add("net.tun_iface", "PASS", "profile", "No common TUN/VPN/container-like interface name found", ifaces)
            code, rules, _ = self.run(["ip", "rule", "show"], timeout=5)
            if code == 0 and re.search(r"lookup\s+(?!main|local|default)\S+", rules):
                self.add("net.policy_route", "WARN", "profile", "Non-default policy routing rules visible", self.redact(rules))
            code, route, _ = self.run(["ip", "route", "show", "default"], timeout=5)
            self.add("net.default_route", "INFO", "profile", "Default route", self.redact(route or "unknown"))
            code, addr, _ = self.run(["ip", "-o", "addr", "show", "scope", "global"], timeout=5)
            if code == 0:
                addrs: list[dict[str, str]] = []
                for line in addr.splitlines():
                    fields = line.split()
                    if len(fields) < 4 or fields[2] not in {"inet", "inet6"}:
                        continue
                    addrs.append({
                        "iface": fields[1],
                        "family": "ipv4" if fields[2] == "inet" else "ipv6",
                        "cidr": fields[3],
                        "kind": self.ip_kind(fields[3]),
                    })
                self.add("net.interface_addresses", "INFO", "profile", "Local global-scope interface IP addresses", addrs or "none found")

        resolv = self.read("/etc/resolv.conf")
        dns_ips = IPV4_RE.findall(resolv)
        cn_dns = [ip for ip in dns_ips if ip in CHINA_DNS]
        if cn_dns:
            self.add("net.dns_cn", "WARN", "profile", "China public DNS resolver found", cn_dns, "Use DNS resolvers matching the intended environment.")
        else:
            self.add("net.dns", "INFO", "profile", "DNS resolver hints", dns_ips or "none found")

        code, ps, _ = self.run(["sh", "-c", "ps -eo pid=,comm=,args= 2>/dev/null"], timeout=6)
        proc_hits = []
        if code == 0:
            for line in ps.splitlines():
                if VPN_PROC_RE.search(line):
                    proc_hits.append(self.redact(line[:300]))
                    if len(proc_hits) >= 20:
                        break
        if proc_hits:
            self.add("net.proxy_process", "FAIL" if self.args.strict_us_workstation else "WARN", "profile", "Proxy/VPN-like processes visible", proc_hits, "Do not hide process facts; use a real US host if this evidence is not acceptable.")
        else:
            self.add("net.proxy_process", "PASS", "profile", "No common proxy/VPN process names found")

        if self.args.no_network:
            self.add("net.egress", "INFO", "runtime", "External egress tests skipped", "--no-network")
            return
        if not shutil.which("curl"):
            self.add("net.egress", "FAIL", "runtime", "Cannot test HTTPS egress", "curl not found")
            return
        default = self.fetch_geo(use_no_proxy=False)
        direct = self.fetch_geo(use_no_proxy=True)
        ipv4 = self.fetch_geo(use_no_proxy=False, ip_version="4")
        ipv6 = self.fetch_geo(use_no_proxy=False, ip_version="6")
        self.facts["egress_default"] = default
        self.facts["egress_no_proxy"] = direct
        self.facts["egress_ipv4"] = ipv4
        self.facts["egress_ipv6"] = ipv6
        self.check_geo("net.egress_default", "Default curl egress", default)
        self.check_geo("net.egress_no_proxy", "No-proxy curl egress", direct)
        self.check_geo("net.egress_ipv4", "IPv4 curl egress", ipv4, required=False)
        self.check_geo("net.egress_ipv6", "IPv6 curl egress", ipv6, required=False)
        if default.get("country") and direct.get("country") and default.get("country") != direct.get("country"):
            self.add("net.egress_mismatch", "WARN", "profile", "Default and no-proxy egress countries differ", {"default": default, "no_proxy": direct}, "This usually means env-proxy routing differs from system routing.")
        if ipv4.get("country") and ipv6.get("country") and ipv4.get("country") != ipv6.get("country"):
            self.add("net.egress_ip_version_mismatch", "WARN", "profile", "IPv4 and IPv6 egress countries differ", {"ipv4": ipv4, "ipv6": ipv6}, "Check whether IPv6 bypasses the intended routing path.")

    def fetch_geo(self, use_no_proxy: bool, ip_version: str = "") -> dict[str, str]:
        base = ["curl", "-fsSL", "--max-time", str(self.args.network_timeout)]
        if ip_version in {"4", "6"}:
            base.append(f"-{ip_version}")
        if use_no_proxy:
            base += ["--noproxy", "*"]
        out: dict[str, str] = {}
        code, trace, err = self.run(base + ["https://cloudflare.com/cdn-cgi/trace"], timeout=self.args.network_timeout + 3)
        if code == 0:
            for line in trace.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k in {"ip", "loc", "colo"}:
                        out[{"ip": "ip_cloudflare", "loc": "country", "colo": "colo"}[k]] = v
        else:
            out["cloudflare_error"] = err or f"exit {code}"
        code, ipinfo, err = self.run(base + ["https://ipinfo.io/json"], timeout=self.args.network_timeout + 3)
        if code == 0:
            try:
                data = json.loads(ipinfo)
                for k in ["ip", "city", "region", "country", "org", "timezone"]:
                    if data.get(k):
                        out[f"ipinfo_{k}" if k == "ip" else k] = str(data[k])
            except Exception as e:
                out["ipinfo_error"] = f"parse: {e}"
        else:
            out["ipinfo_error"] = err or f"exit {code}"
        if not out.get("country") and out.get("loc"):
            out["country"] = out["loc"]
        return out

    def check_geo(self, id_: str, title: str, geo: dict[str, str], required: bool = True) -> None:
        target = self.args.target_country.upper() if self.args.target_country else ""
        country = (geo.get("country") or "").upper()
        useful = bool(geo) and any(not k.endswith("_error") for k in geo)
        if not useful:
            self.add(id_, "FAIL" if required else "INFO", "runtime" if required else "profile", title + (" failed" if required else " unavailable"), geo or "no response")
        elif target and country and country != target:
            self.add(id_, "FAIL", "profile", title + " is outside target country", geo, f"Use a real {target} egress or target host if {target} is required.")
        elif target and not country:
            self.add(id_, "WARN", "profile", title + " country unknown", geo)
        else:
            self.add(id_, "PASS", "profile", title, geo)

    def audit_home(self) -> None:
        if not (self.args.scan_known_home or self.args.scan_home):
            self.add("home.scan", "INFO", "privacy", "HOME residue scan skipped", "Use --scan-known-home or --scan-home to scan paths/counts without printing content.")
            return
        home = Path.home()
        candidates: list[Path] = []
        known = [
            ".bash_history", ".zsh_history", ".profile", ".bashrc", ".zshrc",
            ".config/claude", ".claude", ".codex", ".config/Code/User/settings.json",
        ]
        if self.args.scan_known_home:
            for rel in known:
                p = home / rel
                if p.exists():
                    candidates.append(p)
        if self.args.scan_home:
            skip_dirs = {"Library", "node_modules", ".cache", ".npm", ".local/share/Trash", "Downloads"}
            for root, dirs, files in os.walk(home):
                rootp = Path(root)
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".app")]
                for f in files:
                    if len(candidates) >= self.args.home_max_files:
                        break
                    p = rootp / f
                    if p.is_symlink() or p.stat().st_size > self.args.home_max_bytes:
                        continue
                    if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".sqlite", ".db"}:
                        continue
                    candidates.append(p)
                if len(candidates) >= self.args.home_max_files:
                    break
        seen: set[Path] = set()
        cjk_paths, cn_hint_paths, proxy_paths, claude_paths = [], [], [], []
        for p in candidates[: self.args.home_max_files]:
            try:
                rp = p.resolve()
            except Exception:
                rp = p
            if rp in seen or not p.is_file():
                continue
            seen.add(rp)
            try:
                text = p.read_text(errors="replace")[: self.args.home_max_bytes]
            except Exception:
                continue
            rel = str(p).replace(str(home), "~", 1)
            if CJK_RE.search(text):
                cjk_paths.append(rel)
            if CN_HINT_RE.search(text):
                cn_hint_paths.append(rel)
            if re.search(r"(?i)(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|NO_PROXY|host\.docker\.internal|127\.0\.0\.1:\d{2,5})", text):
                proxy_paths.append(rel)
            if ".claude" in rel or "claude" in text[:5000].lower() or ".codex" in rel:
                claude_paths.append(rel)
        evidence = {
            "files_examined": len(seen),
            "cjk_paths": cjk_paths[:20],
            "cn_hint_paths": cn_hint_paths[:20],
            "proxy_hint_paths": proxy_paths[:20],
            "claude_or_codex_paths": sorted(set(claude_paths))[:20],
        }
        if cjk_paths or cn_hint_paths or proxy_paths:
            self.add("home.residue", "WARN", "profile", "HOME residue hints found", evidence, "Review and clean intentionally; do not delete secrets/history blindly.")
        else:
            self.add("home.residue", "PASS", "profile", "No CJK/CN/proxy residue found in scanned HOME files", evidence)

    def output(self) -> None:
        result, summary = self.headline()
        payload = {
            "result": result,
            "summary": summary,
            "facts": self.facts,
            "checks": [asdict(c) for c in self.checks],
        }
        if self.args.json:
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return
        print(f"# Claude Runtime Audit: {result}\n")
        print(summary)
        print("\n## Facts")
        for k, v in self.facts.items():
            if isinstance(v, dict):
                print(f"- {k}: `{json.dumps(v, ensure_ascii=False)}`")
            else:
                print(f"- {k}: `{self.redact(str(v))}`")
        print("\n## Checks")
        order = {"FAIL": 0, "WARN": 1, "PASS": 2, "INFO": 3}
        for c in sorted(self.checks, key=lambda x: (order.get(x.status, 9), x.id)):
            print(f"\n### [{c.status}] {c.id}: {c.title}")
            if c.evidence:
                ev = self.redact(c.evidence)
                if len(ev) > 1800:
                    ev = ev[:1800] + "\n...<truncated>"
                print("Evidence:")
                print("```text")
                print(ev)
                print("```")
            if c.recommendation:
                print(f"Recommendation: {c.recommendation}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Read-only Claude Code runtime/profile audit for Linux environments.")
    p.add_argument("--target-country", default="US", help="Expected external egress country code, e.g. US. Empty string disables country check.")
    p.add_argument("--target-timezone", default="", help="Expected timezone substring, e.g. America/Los_Angeles. Empty disables strict timezone comparison.")
    p.add_argument("--strict-us-workstation", action="store_true", help="Fail visible Docker/VM/TUN/proxy facts for strict US workstation-like profile.")
    p.add_argument("--scan-known-home", action="store_true", help="Scan known Claude/shell config and history paths, reporting paths/counts only.")
    p.add_argument("--scan-home", action="store_true", help="Broader HOME scan; privacy-preserving but can be slower.")
    p.add_argument("--home-max-files", type=int, default=600, help="Maximum files to scan for --scan-home/--scan-known-home.")
    p.add_argument("--home-max-bytes", type=int, default=1_000_000, help="Maximum bytes read per HOME file.")
    p.add_argument("--no-network", action="store_true", help="Skip external HTTPS/geolocation tests.")
    p.add_argument("--network-timeout", type=int, default=8, help="Curl timeout seconds for each external test.")
    p.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    auditor = Auditor(args)
    auditor.audit_platform()
    auditor.audit_container_vm()
    auditor.audit_locale_time_fonts()
    auditor.audit_network()
    auditor.audit_home()
    auditor.output()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
