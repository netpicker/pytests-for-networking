from comfy import high


@high(
    name="rule_cve202537158",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show running-config | include (https-server|http-server|rest|ssh|web-management|aruba-central|api)",
    ),
)
def rule_cve202537158(configuration, commands, device, devices):
    """
    CVE-2025-37158 - Aruba/HPE AOS-CX Authenticated Command Injection (RCE)

    Advisory: HPESBNW04888 rev.1 - HPE Aruba Networking AOS-CX Multiple Vulnerabilities
    Affected versions (per advisory):
      - 10.16.xxxx: 10.16.1000 and below
      - 10.15.xxxx: 10.15.1020 and below
      - 10.14.xxxx: 10.14.1050 and below
      - 10.13.xxxx: 10.13.1090 and below
      - 10.10.xxxx: 10.10.1160 and below

    This rule is a configuration-aware exposure check:
      - If the device is on a vulnerable version AND remote management services are enabled,
        the device is considered exposed to authenticated remote exploitation paths.
      - If the device is on a fixed version, it is not vulnerable.
      - If the device is on a vulnerable version but remote management is not enabled,
        the rule treats it as a safer configuration (reduced exposure).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpessbnw04888en_us"

    version_output = (commands.show_version or "").strip()
    mgmt_cfg_raw = (commands.show_mgmt_services or "").strip().lower()
    mgmt_cfg = "\n".join(
        line for line in mgmt_cfg_raw.splitlines()
        if not line.strip().startswith("!") and not line.strip().startswith("#")
        and not line.strip().startswith("no ")
    )

    def parse_aoscx_version(text: str):
        """
        Extracts AOS-CX version like 10.15.1020 from 'show version' output.
        Returns tuple(int,int,int) or None.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2)), int(m.group(3))

    v = parse_aoscx_version(version_output)
    if not v:
        # If we cannot determine version, do not assert vulnerability.
        return

    major, minor, patch = v

    # Determine if version is vulnerable based on advisory thresholds.
    vulnerable = False
    if major == 10 and minor == 16 and patch <= 1000:
        vulnerable = True
    elif major == 10 and minor == 15 and patch <= 1020:
        vulnerable = True
    elif major == 10 and minor == 14 and patch <= 1050:
        vulnerable = True
    elif major == 10 and minor == 13 and patch <= 1090:
        vulnerable = True
    elif major == 10 and minor == 10 and patch <= 1160:
        vulnerable = True

    if not vulnerable:
        return

    # Configuration exposure check: remote management services enabled.
    # (Advisory recommends restricting CLI and web-based management interfaces.)
    mgmt_indicators = [
        "ssh server",
        "https-server",
        "http-server",
        "web-management",
        "rest",
        "api",
        "aruba-central",
    ]
    mgmt_enabled = any(ind in mgmt_cfg for ind in mgmt_indicators)

    # If vulnerable version + management enabled => fail.
    assert not mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37158 (AOS-CX authenticated command injection leading to RCE). "
        f"Detected vulnerable AOS-CX version {major}.{minor}.{patch} and remote management services appear enabled "
        f"(SSH/HTTP(S)/REST/API). Upgrade to a fixed release (10.16.1001+, 10.15.1030+, 10.14.1060+, 10.13.1101+, "
        f"10.10.1170+) and restrict management interfaces as recommended. Advisory: {advisory_url}"
    )