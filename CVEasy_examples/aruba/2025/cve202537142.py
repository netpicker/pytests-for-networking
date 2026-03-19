from comfy import high


@high(
    name="rule_cve202537142",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web-server|https-server|http-server|mgmt|management|ssh|telnet|api|papi|netconf|rest|central|allowlist|acl)",
        show_users="show users",
    ),
)
def rule_cve202537142(configuration, commands, device, devices):
    """
    CVE-2025-37142: Authenticated arbitrary file download in CLI binary affecting
    AOS-10 GW and AOS-8 Controller/Mobility Conductor.

    This rule flags devices that:
      1) Run an affected ArubaOS (AOS-10 / AOS-8) version per HPESBNW04957, AND
      2) Expose a remote management path (SSH/Telnet or Web UI) that would allow an authenticated
         actor to reach the vulnerable CLI binary remotely.

    Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").lower()

    def _extract_version(text: str):
        # Common Aruba outputs include "ArubaOS version X.Y.Z.W" or "Version : X.Y.Z.W"
        import re

        m = re.search(r"\b(?:arubaos\s+version|version\s*[:])\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", text, re.I)
        return m.group(1) if m else None

    def _parse(v: str):
        return tuple(int(x) for x in v.split("."))

    running_version = _extract_version(commands.show_version or "")
    if not running_version:
        # If we cannot determine version, do not assert vulnerability.
        return

    v = _parse(running_version)

    # Vulnerable versions per advisory:
    # AOS-10.7.x.x: 10.7.2.0 and below
    # AOS-10.4.x.x: 10.4.1.8 and below
    # AOS-8.13.x.x: 8.13.0.1 and below
    # AOS-8.12.x.x: 8.12.0.5 and below
    # AOS-8.10.x.x: 8.10.0.18 and below
    # (EoM branches are also affected but not patched; we treat them as vulnerable if detected.)
    def _is_vulnerable_version(vt):
        # AOS-10
        if vt[0] == 10:
            if vt[1] == 7:
                return vt <= _parse("10.7.2.0")
            if vt[1] == 4:
                return vt <= _parse("10.4.1.8")
            # EoM branches listed as affected: 10.6.x, 10.5.x, 10.3.x (all)
            if vt[1] in (6, 5, 3):
                return True
            return False

        # AOS-8
        if vt[0] == 8:
            if vt[1] == 13:
                return vt <= _parse("8.13.0.1")
            if vt[1] == 12:
                return vt <= _parse("8.12.0.5")
            if vt[1] == 10:
                return vt <= _parse("8.10.0.18")
            # EoM branches listed as affected: 8.11.x, 8.9.x, 8.8.x, 8.7.x, 8.6.x (all)
            if vt[1] in (11, 9, 8, 7, 6):
                return True
            return False

        return False

    version_vulnerable = _is_vulnerable_version(v)
    if not version_vulnerable:
        return

    # Configuration exposure check (best-effort):
    # The vulnerability requires an authenticated actor; practical risk increases when remote
    # management interfaces are enabled/reachable (SSH/Telnet/Web UI).
    mgmt_cfg = (commands.show_mgmt_services or "").lower()

    # Heuristics: if any of these appear enabled, treat as exposed.
    exposed_indicators = (
        "ssh", "telnet", "web-server", "https-server", "http-server",
        "management", "mgmt", "netconf", "rest", "api", "central", "papi"
    )
    mgmt_lines = [
        line for line in mgmt_cfg.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#")
    ]
    mgmt_cfg_filtered = "\n".join(mgmt_lines)
    mgmt_exposed = any(tok in mgmt_cfg_filtered for tok in exposed_indicators)

    # Additional heuristic: if there are local users configured, the device is more likely to have
    # authenticated access paths. (Does not prove exposure; used only to strengthen signal.)
    users_out = (commands.show_users or "").lower()
    has_users = any(k in users_out for k in ("admin", "user", "username", "role"))

    config_vulnerable = mgmt_exposed and has_users

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37142 (Aruba/HPE ArubaOS). "
        f"Detected vulnerable software version {running_version} and remote management exposure "
        f"(SSH/Telnet/Web/API indicators present) with configured users, enabling an authenticated "
        f"actor to potentially exploit an arbitrary file download flaw in the CLI binary. "
        f"Advisory: {advisory_url}"
    )