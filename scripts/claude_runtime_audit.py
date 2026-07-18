#!/usr/bin/env python3
"""Read-only Claude Code runtime/profile audit for Linux and Windows."""
from __future__ import annotations

import argparse
import ipaddress
import json
import locale
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

SECRET_RE = re.compile(r"(?i)(token|password|passwd|secret|key|authorization|bearer)=([^\s&]+)")
CLI_SECRET_RE = re.compile(r"(?i)(--?(?:token|password|passwd|secret|api[-_]?key|authorization)\s+)(?:\"[^\"]*\"|'[^']*'|\S+)")
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
WINDOWS_VPN_ADAPTER_RE = re.compile(
    r"(?i)(wintun|wireguard|tap-windows|openvpn|tailscale|zerotier|fortinet|anyconnect|globalprotect|"
    r"clash|mihomo|v2ray|sing-box|vpn|hyper-v virtual ethernet|vethernet|docker)"
)
CHINA_DNS = {"114.114.114.114", "223.5.5.5", "223.6.6.6", "180.76.76.76", "119.29.29.29"}
WINDOWS_US_TIMEZONES = {
    "aleutian standard time",
    "alaskan standard time",
    "pacific standard time",
    "us mountain standard time",
    "mountain standard time",
    "central standard time",
    "eastern standard time",
    "us eastern standard time",
    "atlantic standard time",
    "hawaiian standard time",
}
WINDOWS_TIMEZONE_ALIASES = {
    "america/adak": "aleutian standard time",
    "america/anchorage": "alaskan standard time",
    "america/los_angeles": "pacific standard time",
    "america/phoenix": "us mountain standard time",
    "america/denver": "mountain standard time",
    "america/chicago": "central standard time",
    "america/new_york": "eastern standard time",
    "america/indiana/indianapolis": "us eastern standard time",
    "pacific/honolulu": "hawaiian standard time",
}


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
        self.system = platform.system().lower()
        self._powershell_path: Optional[str] = None

    def add(self, id_: str, status: str, severity: str, title: str, evidence: object = "", recommendation: str = "") -> None:
        if isinstance(evidence, (dict, list, tuple)):
            ev = json.dumps(evidence, ensure_ascii=False, indent=2)
        else:
            ev = str(evidence).strip()
        self.checks.append(Check(id_, status, severity, title, ev, recommendation))

    def run(self, cmd: list[str], timeout: int = 6, env: Optional[dict[str, str]] = None) -> tuple[int, str, str]:
        run_cmd = cmd
        if self.system == "windows" and cmd:
            resolved = shutil.which(cmd[0]) or cmd[0]
            if Path(resolved).suffix.lower() in {".cmd", ".bat"}:
                run_cmd = ["cmd.exe", "/d", "/s", "/c", subprocess.list2cmdline([resolved, *cmd[1:]])]
        try:
            p = subprocess.run(run_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, env=env)
            return p.returncode, self.decode_output(p.stdout).strip(), self.decode_output(p.stderr).strip()
        except FileNotFoundError:
            return 127, "", f"command not found: {cmd[0]}"
        except subprocess.TimeoutExpired as e:
            return 124, self.decode_output(e.stdout or b"").strip(), "timeout"
        except Exception as e:  # defensive: audit must not crash
            return 1, "", repr(e)

    def decode_output(self, value: object) -> str:
        if isinstance(value, str):
            return value
        if not isinstance(value, bytes):
            return str(value)
        for encoding in ("utf-8", locale.getpreferredencoding(False), "cp1252"):
            try:
                return value.decode(encoding)
            except (UnicodeDecodeError, LookupError):
                pass
        return value.decode("utf-8", errors="replace")

    def powershell_path(self) -> Optional[str]:
        if self._powershell_path is None:
            self._powershell_path = shutil.which("powershell.exe") or shutil.which("powershell") or shutil.which("pwsh.exe") or shutil.which("pwsh") or ""
        return self._powershell_path or None

    def run_powershell(self, script: str, timeout: int = 12) -> tuple[int, str, str]:
        executable = self.powershell_path()
        if not executable:
            return 127, "", "PowerShell not found"
        prefix = (
            "$ErrorActionPreference='Stop';"
            "$utf8=New-Object System.Text.UTF8Encoding($false);"
            "[Console]::OutputEncoding=$utf8;"
            "$OutputEncoding=$utf8;"
        )
        return self.run(
            [executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", prefix + script],
            timeout=timeout,
        )

    def powershell_json(self, script: str, timeout: int = 12) -> object:
        code, out, err = self.run_powershell(f"& {{ {script} }} | ConvertTo-Json -Compress -Depth 6", timeout=timeout)
        if code != 0 or not out:
            return {"_error": err or f"PowerShell exit {code}"}
        try:
            return json.loads(out)
        except json.JSONDecodeError as exc:
            return {"_error": f"Invalid PowerShell JSON: {exc}", "output": self.redact(out[:500])}

    @staticmethod
    def as_list(value: object) -> list[object]:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @staticmethod
    def without_error(value: object) -> bool:
        return not (isinstance(value, dict) and value.get("_error"))

    def read(self, path: str, limit: int = 12000) -> str:
        try:
            return Path(path).read_text(errors="replace")[:limit]
        except Exception:
            return ""

    def redact(self, s: str) -> str:
        s = URL_CRED_RE.sub(lambda m: m.group("scheme") + "<redacted>@", s)
        s = SECRET_RE.sub(lambda m: f"{m.group(1)}=<redacted>", s)
        s = CLI_SECRET_RE.sub(lambda m: m.group(1) + "<redacted>", s)
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
        if self.system == "windows":
            self.audit_platform_windows()
            return

        os_release = self.read("/etc/os-release")
        pretty = ""
        for line in os_release.splitlines():
            if line.startswith("PRETTY_NAME="):
                pretty = line.split("=", 1)[1].strip().strip('"')
        self.facts["os"] = pretty or platform.system()
        code, uname, _ = self.run(["uname", "-a"])
        self.facts["uname"] = uname if code == 0 else platform.platform()
        if self.system != "linux":
            self.add("os.supported", "FAIL", "runtime", "Target is not Linux or Windows", platform.system(), "Run this audit inside the Linux or native Windows environment where Claude Code will run.")
        else:
            self.add("os.supported", "PASS", "runtime", "Linux userland detected", self.facts["os"])

        code, pid1, _ = self.run(["sh", "-c", "ps -p 1 -o comm= 2>/dev/null || true"])
        self.facts["pid1"] = pid1
        self.add("os.pid1", "INFO", "profile", "PID 1 process", pid1 or "unknown")

        for tool in ["sh", "bash", "zsh", "git", "curl"]:
            path = shutil.which(tool)
            self.add(f"tool.{tool}", "PASS" if path else "WARN", "runtime", f"{tool} availability", path or "not found", "Install it if Claude Code workflows depend on it." if not path else "")

        self.audit_cli_tools()
        self.audit_home_space()

    def audit_platform_windows(self) -> None:
        system_info = self.powershell_json(
            "$os=Get-CimInstance Win32_OperatingSystem;"
            "$cs=Get-CimInstance Win32_ComputerSystem;"
            "[pscustomobject]@{"
            "Caption=$os.Caption;Version=$os.Version;BuildNumber=$os.BuildNumber;"
            "OSArchitecture=$os.OSArchitecture;LastBootUpTime=$os.LastBootUpTime;"
            "Manufacturer=$cs.Manufacturer;Model=$cs.Model;HypervisorPresent=$cs.HypervisorPresent}"
        )
        system_data = system_info if self.without_error(system_info) and isinstance(system_info, dict) else {}
        if system_data:
            self.facts["os"] = system_data.get("Caption") or platform.system()
            self.facts["windows"] = system_data
        else:
            self.facts["os"] = platform.platform()
            self.facts["windows_cim_error"] = system_info

        self.add("os.supported", "PASS", "runtime", "Native Windows userland detected", self.facts["os"])
        version = str(system_data.get("Version", ""))
        try:
            supported_version = int(version.split(".", 1)[0]) >= 10
        except (ValueError, IndexError):
            supported_version = platform.release() in {"10", "11"}
        self.add(
            "os.windows_version",
            "PASS" if supported_version else "FAIL",
            "runtime",
            "Windows version support",
            {"version": version or platform.version(), "build": system_data.get("BuildNumber", "")},
            "Claude Code requires Windows 10 or later." if not supported_version else "",
        )

        architecture = str(system_data.get("OSArchitecture") or platform.machine())
        is_64_bit = "64" in architecture
        self.add(
            "os.windows_architecture",
            "PASS" if is_64_bit else "FAIL",
            "runtime",
            "Windows architecture",
            architecture or "unknown",
            "Use 64-bit Windows; Claude Code does not support 32-bit Windows." if not is_64_bit else "",
        )

        powershell = self.powershell_path()
        self.add(
            "tool.powershell",
            "PASS" if powershell else "FAIL",
            "runtime",
            "PowerShell availability",
            powershell or "not found",
            "Install or restore Windows PowerShell 5.1+ or PowerShell 7+." if not powershell else "",
        )
        cmd = os.environ.get("COMSPEC") or shutil.which("cmd.exe")
        self.add("tool.cmd", "PASS" if cmd else "WARN", "runtime", "Command Prompt availability", cmd or "not found")
        for tool in ["git", "curl"]:
            path = shutil.which(tool)
            recommendation = "Install Git for Windows for the most complete Claude Code shell and Git workflow support." if tool == "git" else "Install curl.exe or use --no-network to skip egress checks."
            self.add(f"tool.{tool}", "PASS" if path else "WARN", "runtime", f"{tool} availability", path or "not found", recommendation if not path else "")

        self.audit_cli_tools()
        self.audit_home_space()

    def audit_cli_tools(self) -> None:
        for tool in ["node", "npm", "claude"]:
            path = shutil.which(tool)
            if not path:
                recommendation = "Install Claude Code before relying on this target." if tool == "claude" else "Node/npm are only required for the npm installation method or project workflows that use them."
                self.add(f"tool.{tool}", "WARN", "profile", f"{tool} availability", "not found", recommendation)
                continue
            code, out, err = self.run([tool, "--version"], timeout=5)
            self.add(f"tool.{tool}", "PASS" if code == 0 else "WARN", "runtime", f"{tool} version", self.redact(out or err or path))

    def audit_home_space(self) -> None:
        try:
            usage = shutil.disk_usage(Path.home())
            gib = 1024 ** 3
            evidence = {"path": str(Path.home()), "total_gib": round(usage.total / gib, 1), "free_gib": round(usage.free / gib, 1)}
            self.add("fs.home_space", "WARN" if usage.free < 2 * gib else "INFO", "runtime", "HOME filesystem space", evidence, "Free disk space before installing dependencies or running large builds." if usage.free < 2 * gib else "")
        except Exception as exc:
            self.add("fs.home_space", "INFO", "runtime", "HOME filesystem space unavailable", repr(exc))

    def audit_container_vm(self) -> None:
        if self.system == "windows":
            self.audit_container_vm_windows()
            return

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

    def audit_container_vm_windows(self) -> None:
        strict = self.args.strict_us_workstation
        container_markers = {
            key: value
            for key in ["CONTAINER_SANDBOX_MOUNT_POINT", "DOTNET_RUNNING_IN_CONTAINER", "CONTAINER_NAME"]
            if (value := os.environ.get(key))
        }
        self.add(
            "virt.container",
            "FAIL" if container_markers and strict else "WARN" if container_markers else "PASS",
            "profile",
            "Windows container environment markers" if container_markers else "No common Windows container environment marker found",
            container_markers,
            "Run on the intended Windows host rather than in a Windows container." if container_markers else "",
        )

        computer = self.facts.get("windows", {})
        if not isinstance(computer, dict):
            computer = {}
        identity = {
            "manufacturer": computer.get("Manufacturer", ""),
            "model": computer.get("Model", ""),
        }
        identity_blob = " ".join(str(v) for v in identity.values())
        vm_words = re.compile(
            r"(?i)(virtual machine|vmware|virtualbox|qemu|kvm|parallels|xen|bochs|"
            r"amazon ec2|google compute engine|digitalocean|openstack|nutanix)"
        )
        if vm_words.search(identity_blob):
            self.add("virt.cim", "FAIL" if strict else "WARN", "profile", "Windows computer identity exposes virtualization/cloud evidence", identity, "Use actual matching hardware if a native physical profile is required.")
        else:
            self.add("virt.cim", "INFO", "profile", "Windows computer identity", identity or "unavailable")

        hypervisor_value = computer.get("HypervisorPresent")
        hypervisor_present = hypervisor_value is True or str(hypervisor_value).lower() == "true"
        if hypervisor_present:
            self.add(
                "virt.hypervisor",
                "WARN",
                "profile",
                "Windows reports a hypervisor is present",
                hypervisor_value,
                "This can indicate a VM, Hyper-V, Windows Sandbox, Credential Guard, or VBS; correlate it with manufacturer/model and guest tools.",
            )
        else:
            self.add("virt.hypervisor", "PASS" if hypervisor_value is not None else "INFO", "profile", "Windows hypervisor-present flag", hypervisor_value if hypervisor_value is not None else "unknown")

        bios = self.powershell_json(
            "$b=Get-CimInstance Win32_BIOS;"
            "[pscustomobject]@{Manufacturer=$b.Manufacturer;SMBIOSBIOSVersion=$b.SMBIOSBIOSVersion;Version=$b.Version}"
        )
        if self.without_error(bios):
            self.add("virt.bios", "INFO", "profile", "Windows BIOS identity", bios)
        else:
            self.add("virt.bios", "INFO", "profile", "Windows BIOS identity unavailable", bios)

        guest_processes = self.powershell_json(
            "Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -match "
            "'^(vmtoolsd|vmwaretray|vboxservice|vboxtray|prl_tools_service|qemu-ga|xenservice|waagent)$' } | "
            "Select-Object Id,ProcessName"
        )
        guest_hits = [x for x in self.as_list(guest_processes) if isinstance(x, dict) and not x.get("_error")]
        if guest_hits:
            self.add("virt.guest_tools", "FAIL" if strict else "WARN", "profile", "Virtual-machine guest tools are running", guest_hits, "Treat guest tools as truthful VM evidence; use matching hardware if a physical profile is required.")
        else:
            self.add("virt.guest_tools", "PASS" if self.without_error(guest_processes) else "INFO", "profile", "No common VM guest-tool process found", guest_processes if not self.without_error(guest_processes) else "")

    def audit_locale_time_fonts(self) -> None:
        if self.system == "windows":
            self.audit_locale_time_fonts_windows()
            return

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

    def windows_timezone_matches(self, target: str, actual: str) -> bool:
        target_key = target.strip().lower()
        actual_key = actual.strip().lower()
        if not target_key or not actual_key:
            return False
        return target_key in actual_key or actual_key in target_key or WINDOWS_TIMEZONE_ALIASES.get(target_key) == actual_key

    def audit_locale_time_fonts_windows(self) -> None:
        locale_info = self.powershell_json(
            "$tz=Get-TimeZone;"
            "$culture=[System.Globalization.CultureInfo]::CurrentCulture;"
            "$ui=[System.Globalization.CultureInfo]::CurrentUICulture;"
            "$systemLocale=$null;try{$systemLocale=(Get-WinSystemLocale).Name}catch{};"
            "$languages=@();try{$languages=@(Get-WinUserLanguageList | ForEach-Object {$_.LanguageTag})}catch{};"
            "[pscustomobject]@{TimeZoneId=$tz.Id;TimeZoneDisplayName=$tz.DisplayName;"
            "Culture=$culture.Name;UICulture=$ui.Name;SystemLocale=$systemLocale;Languages=$languages}"
        )
        info = locale_info if isinstance(locale_info, dict) and self.without_error(locale_info) else {}
        timezone = str(info.get("TimeZoneId", ""))
        target_tz = self.args.target_timezone
        if target_tz and not self.windows_timezone_matches(target_tz, timezone):
            self.add("locale.timezone", "WARN", "profile", "Timezone differs from requested target", locale_info or "unknown", f"Set timezone intentionally if {target_tz} is required. IANA names are mapped to the corresponding Windows timezone ID.")
        elif timezone:
            self.add("locale.timezone", "PASS", "profile", "Timezone", {"id": timezone, "display_name": info.get("TimeZoneDisplayName", "")})
        else:
            self.add("locale.timezone", "INFO", "profile", "Timezone unavailable", locale_info)

        if not target_tz and self.args.strict_us_workstation and (self.args.target_country or "").upper() == "US":
            if timezone.lower() in WINDOWS_US_TIMEZONES:
                self.add("locale.timezone_us_profile", "PASS", "profile", "Timezone is compatible with a US target profile", timezone)
            else:
                self.add("locale.timezone_us_profile", "WARN", "profile", "Strict US profile has no explicit US timezone target", timezone or "unknown", "Pass --target-timezone America/<city> or a Windows timezone ID to make validation explicit.")

        time_service = self.powershell_json("Get-Service W32Time -ErrorAction SilentlyContinue | Select-Object Status,StartType,Name")
        if self.without_error(time_service) and time_service:
            self.add("time.windows_time_service", "INFO", "runtime", "Windows Time service", time_service)

        culture_values = [str(info.get(key, "")) for key in ["Culture", "UICulture", "SystemLocale"]]
        languages = [str(x) for x in self.as_list(info.get("Languages"))]
        language_blob = "\n".join(x for x in [*culture_values, *languages] if x)
        if re.search(r"(?i)\ben-US\b", language_blob):
            self.add("locale.current", "PASS", "profile", "Current Windows locale includes en-US", info)
        elif language_blob:
            self.add("locale.current", "WARN", "profile", "Current Windows locale is not clearly en-US", info, "Use a deliberate Windows culture and display language matching the target profile.")
        else:
            self.add("locale.current", "INFO", "profile", "Current Windows locale unavailable", locale_info)

        zh_enabled = sorted({value for value in [*culture_values, *languages] if re.search(r"(?i)^zh(?:-|_)", value)})
        if zh_enabled:
            self.add("locale.zh_enabled", "WARN", "profile", "Chinese Windows language or locale enabled", zh_enabled, "Remove unused language packs only if they are not intentionally part of this machine.")
        else:
            self.add("locale.zh_enabled", "PASS", "profile", "No enabled Chinese Windows language or locale found")

        fonts = self.powershell_json(
            "$key=Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Fonts';"
            "$key.PSObject.Properties | Where-Object {$_.Name -notmatch '^PS'} | ForEach-Object {$_.Name}"
        )
        font_names = [str(x) for x in self.as_list(fonts) if not isinstance(x, dict)]
        cjk_hits = [name for name in font_names if re.search(r"(?i)(noto.*cjk|source han|simsun|simhei|yahei|mingliu|meiryo|malgun|fangsong|kaiti|dengxian|cjk)", name)][:20]
        if cjk_hits:
            self.add("font.cjk", "WARN", "profile", "CJK font hints installed", cjk_hits, "Remove fonts only if the target profile intentionally should not include them.")
        elif self.without_error(fonts):
            self.add("font.cjk", "PASS", "profile", "No obvious CJK font hints found")
        else:
            self.add("font.cjk", "INFO", "profile", "Windows font inventory unavailable", fonts)

    def audit_network(self) -> None:
        proxy_env = {k: self.redact(v) for k, v in os.environ.items() if k in PROXY_ENV_NAMES and v}
        active_proxy_env = {k: v for k, v in proxy_env.items() if k.lower() != "no_proxy"}
        if active_proxy_env:
            self.add("net.proxy_env", "FAIL" if self.args.strict_us_workstation else "WARN", "profile", "Active proxy environment variables visible", proxy_env, "For global routing, prefer real network design; do not rely on hidden env vars for strict profiles.")
        elif proxy_env:
            self.add("net.proxy_env", "INFO", "profile", "Only NO_PROXY/no_proxy environment variables visible", proxy_env)
        else:
            self.add("net.proxy_env", "PASS", "profile", "No proxy env variables visible")

        if self.system == "windows":
            self.audit_network_windows_local()
            self.audit_external_network()
            return

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

        self.audit_external_network()

    def audit_network_windows_local(self) -> None:
        adapters = self.powershell_json(
            "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            "Select-Object -First 100 Name,InterfaceDescription,Status,LinkSpeed,ifIndex"
        )
        adapter_items = [x for x in self.as_list(adapters) if isinstance(x, dict) and not x.get("_error")]
        vpn_adapters = [
            item for item in adapter_items
            if WINDOWS_VPN_ADAPTER_RE.search(f"{item.get('Name', '')} {item.get('InterfaceDescription', '')}")
        ]
        if vpn_adapters:
            self.add("net.tun_iface", "FAIL" if self.args.strict_us_workstation else "WARN", "profile", "VPN/TUN/container-like Windows adapters visible", vpn_adapters, "Visible adapters are runtime facts; disclose them or use the intended target network.")
        else:
            self.add("net.tun_iface", "PASS" if self.without_error(adapters) else "INFO", "profile", "No common VPN/TUN/container-like Windows adapter found", adapter_items if self.without_error(adapters) else adapters)

        addresses = self.powershell_json(
            "Get-NetIPAddress -ErrorAction SilentlyContinue | Where-Object {"
            "$_.IPAddress -notlike 'fe80:*' -and $_.IPAddress -ne '127.0.0.1' -and $_.IPAddress -ne '::1'} | "
            "Select-Object InterfaceAlias,@{n='Family';e={$_.AddressFamily.ToString()}},IPAddress,PrefixLength,PrefixOrigin"
        )
        address_items = [x for x in self.as_list(addresses) if isinstance(x, dict) and not x.get("_error")]
        normalized_addresses = []
        for item in address_items:
            ip = str(item.get("IPAddress", ""))
            prefix = item.get("PrefixLength", "")
            cidr = f"{ip}/{prefix}" if ip and prefix != "" else ip
            normalized_addresses.append({**item, "Kind": self.ip_kind(cidr) if cidr else "unknown"})
        self.add("net.interface_addresses", "INFO", "profile", "Local Windows interface IP addresses", normalized_addresses if normalized_addresses else addresses)

        routes = self.powershell_json(
            "Get-NetRoute -ErrorAction SilentlyContinue | Where-Object {"
            "$_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0'} | "
            "Sort-Object RouteMetric | Select-Object DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,PolicyStore"
        )
        self.add("net.default_route", "INFO", "profile", "Windows default routes", routes)

        dns = self.powershell_json(
            "Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Where-Object {$_.ServerAddresses.Count -gt 0} | "
            "Select-Object InterfaceAlias,@{n='Family';e={$_.AddressFamily.ToString()}},ServerAddresses"
        )
        dns_items = [x for x in self.as_list(dns) if isinstance(x, dict) and not x.get("_error")]
        dns_ips = []
        for item in dns_items:
            dns_ips.extend(str(x) for x in self.as_list(item.get("ServerAddresses")))
        cn_dns = sorted({ip for ip in dns_ips if ip in CHINA_DNS})
        if cn_dns:
            self.add("net.dns_cn", "WARN", "profile", "China public DNS resolver found", {"matches": cn_dns, "interfaces": dns_items}, "Use DNS resolvers matching the intended environment.")
        else:
            self.add("net.dns", "INFO", "profile", "Windows DNS resolver hints", dns_items if dns_items else dns)

        user_proxy = self.powershell_json(
            "$p=Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';"
            "[pscustomobject]@{ProxyEnable=[bool]$p.ProxyEnable;ProxyServer=$p.ProxyServer;AutoConfigURL=$p.AutoConfigURL}"
        )
        proxy_active = False
        if isinstance(user_proxy, dict) and self.without_error(user_proxy):
            proxy_active = bool(user_proxy.get("ProxyEnable") or user_proxy.get("AutoConfigURL"))
        self.add(
            "net.windows_user_proxy",
            "FAIL" if proxy_active and self.args.strict_us_workstation else "WARN" if proxy_active else "PASS" if self.without_error(user_proxy) else "INFO",
            "profile",
            "Windows user proxy or PAC configuration is active" if proxy_active else "Windows user proxy configuration",
            self.redact(json.dumps(user_proxy, ensure_ascii=False)),
            "Review the Windows proxy/PAC configuration and use a network design consistent with the intended host." if proxy_active else "",
        )
        code, winhttp, err = self.run(["netsh", "winhttp", "dump"], timeout=6)
        winhttp_active = code == 0 and bool(re.search(r"(?im)^\s*set\s+proxy\b", winhttp))
        self.add(
            "net.winhttp_proxy",
            "FAIL" if winhttp_active and self.args.strict_us_workstation else "WARN" if winhttp_active else "PASS" if code == 0 else "INFO",
            "profile",
            "WinHTTP proxy configuration is active" if winhttp_active else "WinHTTP proxy configuration",
            self.redact(winhttp or err or "unavailable"),
            "Review the WinHTTP proxy and use a network design consistent with the intended host." if winhttp_active else "",
        )

        processes = self.powershell_json(
            "Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | Where-Object {"
            "$_.Name -match '(sing-box|clash|mihomo|v2ray|xray|hysteria|wireguard|tailscale|zerotier|openvpn|gost|trojan|shadowsocks|privoxy|mitmproxy|squid)' "
            "-or $_.CommandLine -match '(sing-box|clash|mihomo|v2ray|xray|hysteria|wireguard|tailscale|zerotier|openvpn|gost|trojan|shadowsocks|privoxy|mitmproxy|squid)'} | "
            "Select-Object -First 20 ProcessId,Name,CommandLine"
        )
        process_hits = []
        for item in self.as_list(processes):
            if not isinstance(item, dict) or item.get("_error"):
                continue
            sanitized = dict(item)
            sanitized["CommandLine"] = self.redact(str(sanitized.get("CommandLine", ""))[:300])
            process_hits.append(sanitized)
        if process_hits:
            self.add("net.proxy_process", "FAIL" if self.args.strict_us_workstation else "WARN", "profile", "Proxy/VPN-like Windows processes visible", process_hits, "Do not hide process facts; use a real target host if this evidence is not acceptable.")
        else:
            self.add("net.proxy_process", "PASS" if self.without_error(processes) else "INFO", "profile", "No common proxy/VPN process names found", processes if not self.without_error(processes) else "")

    def audit_external_network(self) -> None:
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
            home / ".bash_history", home / ".zsh_history", home / ".profile", home / ".bashrc", home / ".zshrc",
            home / ".config/claude", home / ".claude", home / ".codex", home / ".config/Code/User/settings.json",
        ]
        if self.system == "windows":
            appdata = Path(os.environ.get("APPDATA", home / "AppData/Roaming"))
            known.extend([
                home / ".gitconfig",
                appdata / "Claude",
                appdata / "Code/User/settings.json",
                appdata / "Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
                appdata / "Microsoft/PowerShell/PSReadLine/ConsoleHost_history.txt",
                home / "Documents/WindowsPowerShell",
                home / "Documents/PowerShell",
            ])
        if self.args.scan_known_home:
            for p in known:
                if p.is_file():
                    candidates.append(p)
                elif p.is_dir():
                    for root, dirs, files in os.walk(p):
                        dirs[:] = [d for d in dirs if d not in {"node_modules", "Cache", "cache"}]
                        for filename in files:
                            candidates.append(Path(root) / filename)
                            if len(candidates) >= self.args.home_max_files:
                                break
                        if len(candidates) >= self.args.home_max_files:
                            break
                if len(candidates) >= self.args.home_max_files:
                    break
        if self.args.scan_home:
            skip_dirs = {"Library", "AppData", "node_modules", ".cache", ".npm", "Trash", "Downloads"}
            for root, dirs, files in os.walk(home):
                rootp = Path(root)
                dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".app")]
                for f in files:
                    if len(candidates) >= self.args.home_max_files:
                        break
                    p = rootp / f
                    try:
                        too_large = p.stat().st_size > self.args.home_max_bytes
                    except OSError:
                        continue
                    if p.is_symlink() or too_large:
                        continue
                    if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".sqlite", ".db", ".exe", ".dll", ".pdb", ".woff", ".woff2", ".ttf", ".otf"}:
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
            try:
                if p.stat().st_size > self.args.home_max_bytes:
                    continue
            except OSError:
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
    p = argparse.ArgumentParser(description="Read-only Claude Code runtime/profile audit for Linux and native Windows environments.")
    p.add_argument("--target-country", default="US", help="Expected external egress country code, e.g. US. Empty string disables country check.")
    p.add_argument("--target-timezone", default="", help="Expected IANA or Windows timezone, e.g. America/Los_Angeles or Pacific Standard Time. Empty disables strict comparison.")
    p.add_argument("--strict-us-workstation", action="store_true", help="Fail visible Docker/VM/TUN/proxy facts for strict US workstation-like profile.")
    p.add_argument("--scan-known-home", action="store_true", help="Scan known Claude, shell/PowerShell, and editor config/history paths, reporting paths/counts only.")
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
