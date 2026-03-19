from comfy import high


@high(
    name="rule_cve202537160",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_mgmt_config="show running-config | include (https-server|http-server|web|rest|api|mgmt|management)",
    ),
)
def rule_cve202537160(configuration, commands, device, devices):
    """
    CVE-2025-37160: Authenticated Broken Access Control (BAC) in REST API Configuration Service
    in the AOS-CX web-based management interface may allow a low-privileged authenticated user
    to view sensitive information.

    This rule:
      1) Detects whether the device is running an affected AOS-CX version branch/build.
      2) Checks whether the web-based management interface is enabled (prerequisite for exploitation).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04888en_us"

    version_output = (commands.show_version or "").strip()

    def _parse_aoscx_version(text: str):
        """
        Extracts AOS-CX version like 10.14.1050 from 'show version' output.
        Returns (major, minor, patch) as ints, or None if not found.
        """
        import re

        m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", text)
        if not m:
            return None
        return int(m.group(1)), int(m.group(2)), int(m.group(3))

    v = _parse_aoscx_version(version_output)
    if not v:
        # If we cannot determine version, do not fail the device (avoid false positives).
        return

    major, minor, patch = v

    # Affected versions per advisory:
    # 10.16.1000 and below; 10.15.1020 and below; 10.14.1050 and below;
    # 10.13.1090 and below; 10.10.1160 and below.
    vulnerable_thresholds = {
        (10, 16): 1000,
        (10, 15): 1020,
        (10, 14): 1050,
        (10, 13): 1090,
        (10, 10): 1160,
    }

    version_vulnerable = False
    if (major, minor) in vulnerable_thresholds:
        version_vulnerable = patch <= vulnerable_thresholds[(major, minor)]

    if not version_vulnerable:
        return

    # Configuration prerequisite: web-based management interface enabled.
    # Advisory describes BAC in web-based management interface / REST API configuration service.
    mgmt_cfg_raw = (commands.show_mgmt_config or "").lower()
    mgmt_cfg = "\n".join(
        line for line in mgmt_cfg_raw.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#")
    )

    web_mgmt_enabled = any(
        token in mgmt_cfg
        for token in [
            "https-server",
            "http-server",
            "web-management",
            "web mgmt",
            "rest",
            "api",
        ]
    )

    # If web management is not enabled, treat as safe configuration for this specific BAC exposure.
    if not web_mgmt_enabled:
        assert True
        return

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37160 (Authenticated Broken Access Control) "
        f"because it is running an affected AOS-CX version ({major}.{minor}.{patch}) and the web-based "
        f"management interface/REST API appears enabled, which may allow a low-privileged authenticated "
        f"user to view sensitive information. Advisory: {advisory_url}"
    )