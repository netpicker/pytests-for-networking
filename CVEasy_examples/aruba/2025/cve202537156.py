from comfy import high


@high(
    name="rule_cve202537156",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show running-config | include (https-server|http-server|ssh|telnet|rest|api|web)",
        show_users="show running-config | include (username|user)",
    ),
)
def rule_cve202537156(configuration, commands, device, devices):
    """
    CVE-2025-37156 (ArubaOS-CX): Platform-level DoS that can render the switch non-bootable.
    Advisory: HPESBNW04888 rev.1 (2025-11-18)

    This CVE requires administrative access. As a configuration-level risk reduction,
    this rule flags devices that are BOTH:
      1) Running an affected AOS-CX version, AND
      2) Exposing remote management services (increasing likelihood of admin access being obtained/used remotely)

    Note: The advisory's workaround recommends restricting CLI and web-based management interfaces
    to a dedicated L2 segment/VLAN and/or controlling by firewall policies. This rule uses
    management-service enablement as a practical proxy signal.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04888en_us"

    version_output = (commands.show_version or "").lower()

    def _parse_aoscx_version(text: str):
        """
        Extracts AOS-CX version like 10.16.1000 from 'show version' output.
        Returns tuple(int major, int minor, int patch) or None.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2)), int(m.group(3))

    ver = _parse_aoscx_version(version_output)
    if not ver:
        # If we cannot determine version, do not fail the test (avoid false positives).
        return

    major, minor, patch = ver

    # Affected (<=) per advisory:
    # 10.16.1000 and below
    # 10.15.1020 and below
    # 10.14.1050 and below
    # 10.13.1090 and below
    # 10.10.1160 and below
    vulnerable_thresholds = {
        (10, 16): 1000,
        (10, 15): 1020,
        (10, 14): 1050,
        (10, 13): 1090,
        (10, 10): 1160,
    }

    is_vulnerable_version = (major, minor) in vulnerable_thresholds and patch <= vulnerable_thresholds[(major, minor)]
    if not is_vulnerable_version:
        return

    mgmt_cfg_raw = (commands.show_mgmt_services or "").lower()
    mgmt_cfg = "\n".join(
        line for line in mgmt_cfg_raw.splitlines()
        if not line.strip().startswith("!") and not line.strip().startswith("#")
        and not line.strip().startswith("no ")
    )
    users_cfg = (commands.show_users or "").lower()

    # "Vulnerable configuration" proxy:
    # Remote management services enabled (SSH and/or Web UI/API).
    # This aligns with the advisory workaround to restrict CLI/web management exposure.
    ssh_enabled = "ssh server" in mgmt_cfg or "ssh enable" in mgmt_cfg
    web_enabled = "https-server" in mgmt_cfg or "http-server" in mgmt_cfg
    rest_enabled = "rest" in mgmt_cfg or "api" in mgmt_cfg

    remote_mgmt_exposed = ssh_enabled or web_enabled or rest_enabled

    # "Safe configuration" proxy:
    # No remote management services enabled (local/console-only admin access).
    if not remote_mgmt_exposed:
        return

    # Additional context: presence of local admin users indicates admin access exists (expected),
    # but we include it in the message for operator clarity.
    has_local_users = "username" in users_cfg or "user" in users_cfg

    assert False, (
        f"Device {device.name} is potentially vulnerable to CVE-2025-37156 (ArubaOS-CX platform-level DoS). "
        f"Detected affected AOS-CX version {major}.{minor}.{patch} (<= {major}.{minor}.{vulnerable_thresholds[(major, minor)]}) "
        f"with remote management services enabled "
        f"(ssh={ssh_enabled}, web={web_enabled}, rest/api={rest_enabled}). "
        "This CVE can be exploited by an attacker with administrative access to execute specific code that may render the switch "
        "non-bootable and non-functional. "
        "Mitigation per advisory: restrict CLI and web-based management interfaces to a dedicated L2 segment/VLAN and/or control via "
        "firewall policies and accounting controls. "
        f"Local users present={has_local_users}. "
        f"Advisory: {advisory_url}"
    )