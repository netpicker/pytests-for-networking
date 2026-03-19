from comfy import high


@high(
    name="rule_cve202537138",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show mgmt-services",
        show_running_config="show running-config",
    ),
)
def rule_cve202537138(configuration, commands, device, devices):
    """
    CVE-2025-37138: Authenticated command injection in CLI binary (physical access required)
    affecting AOS-10 Gateways and AOS-8 Controllers/Mobility Conductor.

    This rule flags devices that:
      1) Run an affected (vulnerable) AOS-10/AOS-8 version, AND
      2) Have local/physical CLI access paths enabled (e.g., console/serial login enabled).

    Note: The advisory states exploitation requires physical access. Therefore, this rule
    treats "console/serial access enabled" as the vulnerable configuration condition.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").lower()

    def _extract_version(text: str):
        # Common ArubaOS outputs include:
        # "ArubaOS version 10.7.2.0"
        # "ArubaOS Version 8.12.0.5"
        import re

        m = re.search(r"\b(?:arubaos\s+)?version\s+(\d+\.\d+\.\d+\.\d+)\b", text, re.IGNORECASE)
        return m.group(1) if m else None

    def _ver_tuple(v: str):
        return tuple(int(x) for x in v.split("."))

    def _in_range(v: str, low: str, high: str):
        # inclusive range: low <= v <= high
        vt = _ver_tuple(v)
        return _ver_tuple(low) <= vt <= _ver_tuple(high)

    current_version = _extract_version(commands.show_version or "")
    if not current_version:
        # If we cannot determine version, do not assert vulnerability.
        return

    # Vulnerable versions per HPESBNW04957 rev.1:
    # AOS-10.7.x.x: 10.7.2.0 and below
    # AOS-10.4.x.x: 10.4.1.8 and below
    # AOS-8.13.x.x: 8.13.0.1 and below
    # AOS-8.12.x.x: 8.12.0.5 and below
    # AOS-8.10.x.x: 8.10.0.18 and below
    # EoM branches are also affected (not patched): AOS-10.6/10.5/10.3, AOS-8.11/8.9/8.8/8.7/8.6/6.5.4
    v = current_version

    version_vulnerable = False

    # AOS-10 vulnerable branches
    if v.startswith("10.7."):
        version_vulnerable = _in_range(v, "10.7.0.0", "10.7.2.0")
    elif v.startswith("10.4."):
        version_vulnerable = _in_range(v, "10.4.0.0", "10.4.1.8")
    elif v.startswith("10.6.") or v.startswith("10.5.") or v.startswith("10.3."):
        version_vulnerable = True

    # AOS-8 vulnerable branches
    elif v.startswith("8.13."):
        version_vulnerable = _in_range(v, "8.13.0.0", "8.13.0.1")
    elif v.startswith("8.12."):
        version_vulnerable = _in_range(v, "8.12.0.0", "8.12.0.5")
    elif v.startswith("8.10."):
        version_vulnerable = _in_range(v, "8.10.0.0", "8.10.0.18")
    elif v.startswith("8.11.") or v.startswith("8.9.") or v.startswith("8.8.") or v.startswith("8.7.") or v.startswith("8.6.") or v.startswith("6.5.4."):
        version_vulnerable = True

    if not version_vulnerable:
        return

    # Configuration check: physical/local CLI access paths enabled.
    # We look for console/serial login being enabled in either mgmt-services or running-config output.
    def _active_lines(text):
        """Return only positive config lines (skip comments/negations)."""
        result = []
        for line in text.lower().splitlines():
            s = line.strip()
            if not s:
                continue
            if s.startswith("#") or s.startswith("!"):
                continue
            if s.startswith("no "):
                continue
            result.append(s)
        return "\n".join(result)

    mgmt_services = _active_lines(commands.show_mgmt_services or "")
    running_cfg = _active_lines(commands.show_running_config or "")
    combined = "\n".join([mgmt_services, running_cfg])

    # Heuristics to detect enabled console/serial access.
    # Different ArubaOS builds may represent this differently; we match common tokens.
    console_enabled = any(
        token in combined
        for token in [
            "console enable",
            "serial enable",
            "local-console enable",
            "console access enable",
            "enable console",
            "console: enabled",
            "serial: enabled",
        ]
    )

    # If console/serial is not enabled, exploitation requiring physical access is mitigated.
    if not console_enabled:
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37138 (Aruba/HPE ArubaOS). "
        f"Detected vulnerable ArubaOS version '{current_version}' and local/physical CLI access "
        f"(console/serial) appears enabled, which may allow an authenticated actor with physical access "
        f"to trigger command injection in the CLI binary and execute arbitrary commands as a privileged user. "
        f"Advisory: {advisory_url}"
    )