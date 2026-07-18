import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import claude_runtime_audit as audit  # noqa: E402


class FakeWindowsAuditor(audit.Auditor):
    def __init__(self, args):
        super().__init__(args)
        self.system = "windows"

    def powershell_path(self):
        return r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

    def powershell_json(self, script, timeout=12):
        fixtures = [
            ("Win32_OperatingSystem", {
                "Caption": "Microsoft Windows 11 Pro",
                "Version": "10.0.26100",
                "BuildNumber": "26100",
                "OSArchitecture": "64-bit",
                "LastBootUpTime": "2026-07-18T08:00:00",
                "Manufacturer": "Dell Inc.",
                "Model": "Precision 3680",
                "HypervisorPresent": False,
            }),
            ("Win32_BIOS", {"Manufacturer": "Dell Inc.", "SMBIOSBIOSVersion": "2.0.0", "Version": "DELL"}),
            ("Get-Process", []),
            ("Get-TimeZone", {
                "TimeZoneId": "Pacific Standard Time",
                "TimeZoneDisplayName": "(UTC-08:00) Pacific Time (US & Canada)",
                "Culture": "en-US",
                "UICulture": "en-US",
                "SystemLocale": "en-US",
                "Languages": ["en-US"],
            }),
            ("Get-Service W32Time", {"Status": "Running", "StartType": "Manual", "Name": "W32Time"}),
            ("CurrentVersion\\Fonts", ["Segoe UI (TrueType)", "Consolas (TrueType)"]),
            ("Get-NetAdapter", [
                {"Name": "Ethernet", "InterfaceDescription": "Intel Ethernet", "Status": "Up", "ifIndex": 3},
                {"Name": "WireGuard Tunnel", "InterfaceDescription": "WireGuard Tunnel", "Status": "Up", "ifIndex": 8},
            ]),
            ("Get-NetIPAddress", [
                {"InterfaceAlias": "Ethernet", "Family": "IPv4", "IPAddress": "192.168.1.10", "PrefixLength": 24, "PrefixOrigin": "Dhcp"},
            ]),
            ("Get-NetRoute", {"DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.1.1", "InterfaceAlias": "Ethernet", "RouteMetric": 25}),
            ("Get-DnsClientServerAddress", {"InterfaceAlias": "Ethernet", "Family": "IPv4", "ServerAddresses": ["8.8.8.8"]}),
            ("Internet Settings", {"ProxyEnable": False, "ProxyServer": None, "AutoConfigURL": None}),
            ("Win32_Process", []),
        ]
        for marker, value in fixtures:
            if marker in script:
                return value
        return {"_error": f"missing fixture for {script[:80]}"}

    def run(self, cmd, timeout=6, env=None):
        if cmd[:3] == ["netsh", "winhttp", "dump"]:
            return 0, "pushd winhttp\nreset proxy\npopd", ""
        if cmd and cmd[-1] == "--version":
            return 0, "1.0.0", ""
        return 0, "", ""


def fake_which(command):
    paths = {
        "powershell.exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "cmd.exe": r"C:\Windows\System32\cmd.exe",
        "git": r"C:\Program Files\Git\cmd\git.exe",
        "curl": r"C:\Windows\System32\curl.exe",
        "node": r"C:\Program Files\nodejs\node.exe",
        "npm": r"C:\Program Files\nodejs\npm.cmd",
        "claude": r"C:\Users\test\.local\bin\claude.exe",
    }
    return paths.get(command)


class WindowsAuditTests(unittest.TestCase):
    def make_auditor(self, *extra_args):
        args = audit.parse_args(["--no-network", *extra_args])
        return FakeWindowsAuditor(args)

    @mock.patch.object(audit.shutil, "which", side_effect=fake_which)
    def test_native_windows_audit_uses_windows_collectors(self, _which):
        auditor = self.make_auditor("--target-timezone", "America/Los_Angeles")

        auditor.audit_platform()
        auditor.audit_container_vm()
        auditor.audit_locale_time_fonts()
        auditor.audit_network()

        checks = {check.id: check for check in auditor.checks}
        self.assertEqual(checks["os.supported"].status, "PASS")
        self.assertEqual(checks["os.windows_version"].status, "PASS")
        self.assertEqual(checks["os.windows_architecture"].status, "PASS")
        self.assertEqual(checks["locale.timezone"].status, "PASS")
        self.assertEqual(checks["net.tun_iface"].status, "WARN")
        self.assertEqual(checks["net.windows_user_proxy"].status, "PASS")
        self.assertEqual(checks["net.winhttp_proxy"].status, "PASS")
        self.assertEqual(checks["net.egress"].status, "INFO")
        self.assertNotIn("os.pid1", checks)

    @mock.patch.object(audit.shutil, "which", side_effect=fake_which)
    def test_strict_profile_fails_visible_windows_vpn_adapter(self, _which):
        auditor = self.make_auditor("--strict-us-workstation")
        auditor.audit_network()
        checks = {check.id: check for check in auditor.checks}
        self.assertEqual(checks["net.tun_iface"].status, "FAIL")

    def test_strict_profile_fails_active_winhttp_proxy(self):
        auditor = self.make_auditor("--strict-us-workstation")
        auditor.run = mock.Mock(return_value=(0, 'pushd winhttp\nset proxy proxy-server="proxy.example:8080"\npopd', ""))

        auditor.audit_network_windows_local()

        check = next(check for check in auditor.checks if check.id == "net.winhttp_proxy")
        self.assertEqual(check.status, "FAIL")
        self.assertIn("set proxy", check.evidence)

    def test_windows_cmd_wrapper_and_secret_redaction(self):
        auditor = self.make_auditor()
        completed = subprocess.CompletedProcess([], 0, stdout=b"10.9.0\n", stderr=b"")
        with mock.patch.object(audit.shutil, "which", return_value=r"C:\Program Files\nodejs\npm.cmd"), mock.patch.object(audit.subprocess, "run", return_value=completed) as run:
            code, out, _ = audit.Auditor.run(auditor, ["npm", "--version"])

        self.assertEqual((code, out), (0, "10.9.0"))
        command = run.call_args.args[0]
        self.assertEqual(command[:4], ["cmd.exe", "/d", "/s", "/c"])
        self.assertIn("npm.cmd", command[4])
        self.assertEqual(auditor.redact("tool --token abc123 --api-key=secret"), "tool --token <redacted> --api-key=<redacted>")

    def test_windows_known_home_scan_includes_powershell_history(self):
        auditor = self.make_auditor("--scan-known-home")
        with tempfile.TemporaryDirectory() as temp:
            home = Path(temp)
            history = home / "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"
            history.parent.mkdir(parents=True)
            history.write_text("$env:HTTPS_PROXY='http://127.0.0.1:7890'\n", encoding="utf-8")
            claude_settings = home / ".claude/settings.json"
            claude_settings.parent.mkdir()
            claude_settings.write_text('{"language":"zh_CN"}', encoding="utf-8")

            with mock.patch.object(audit.Path, "home", return_value=home), mock.patch.dict(os.environ, {"APPDATA": str(home / "AppData/Roaming")}):
                auditor.audit_home()

        check = next(check for check in auditor.checks if check.id == "home.residue")
        self.assertEqual(check.status, "WARN")
        self.assertIn("ConsoleHost_history.txt", check.evidence)
        self.assertIn("~/.claude/settings.json", check.evidence)


if __name__ == "__main__":
    unittest.main()
