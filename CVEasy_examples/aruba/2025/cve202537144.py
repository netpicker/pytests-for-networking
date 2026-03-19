from comfy import high


@high(
    name="rule_cve202537144",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web-server|https|http|mgmt|management|cli|ssh|telnet|api|papi|rest|netconf|snmp)",
    ),
)
def rule_cve202537144(configuration, commands, device, devices):
    """
    CVE-2025-37144: Authenticated arbitrary file download in a low-level interface library
    affecting AOS-10 GW and AOS-8 Controller/Mobility Conductor web-based management interface.

    This rule flags devices that:
      1) Run an affected (vulnerable) AOS-10/AOS-8 version per HPESBNW04957, AND
      2) Have remote management access enabled (web/https/http or API/SSH), increasing exposure
         to authenticated remote exploitation paths.

    Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").lower()

    # Affected software versions (inclusive "and below" within listed trains):
    # AOS-10.7.x.x: 10.7.2.0 and below (fixed: 10.7.2.1+)
    # AOS-10.4.x.x: 10.4.1.8 and below (fixed: 10.4.1.9+)
    # AOS-8.13.x.x: 8.13.0.1 and below (fixed: 8.13.1.0+)
    # AOS-8.12.x.x: 8.12.0.5 and below (fixed: 8.12.0.6+)
    # AOS-8.10.x.x: 8.10.0.18 and below (fixed: 8.10.0.19+)
    #
    # Note: EoM branches listed as affected but not addressed: AOS-10.6/10.5/10.3, AOS-8.11/8.9/8.8/8.7/8.6, AOS-6.5.4
    vulnerable_markers = [
        # AOS-10.7 vulnerable up to 10.7.2.0
        "10.7.0.", "10.7.1.", "10.7.2.0",
        # AOS-10.4 vulnerable up to 10.4.1.8
        "10.4.0.", "10.4.1.0", "10.4.1.1", "10.4.1.2", "10.4.1.3", "10.4.1.4", "10.4.1.5", "10.4.1.6", "10.4.1.7", "10.4.1.8",
        # EoM AOS-10 branches (all affected)
        "10.6.", "10.5.", "10.3.",
        # AOS-8.13 vulnerable up to 8.13.0.1
        "8.13.0.0", "8.13.0.1",
        # AOS-8.12 vulnerable up to 8.12.0.5
        "8.12.0.0", "8.12.0.1", "8.12.0.2", "8.12.0.3", "8.12.0.4", "8.12.0.5",
        # AOS-8.10 vulnerable up to 8.10.0.18
        "8.10.0.0", "8.10.0.1", "8.10.0.2", "8.10.0.3", "8.10.0.4", "8.10.0.5", "8.10.0.6", "8.10.0.7", "8.10.0.8", "8.10.0.9",
        "8.10.0.10", "8.10.0.11", "8.10.0.12", "8.10.0.13", "8.10.0.14", "8.10.0.15", "8.10.0.16", "8.10.0.17", "8.10.0.18",
        # EoM AOS-8 branches (all affected)
        "8.11.", "8.9.", "8.8.", "8.7.", "8.6.",
        # EoM AOS-6.5.4 (all affected)
        "6.5.4.",
    ]

    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        return

    mgmt_cfg = (commands.show_mgmt_services or "").lower()

    # "Vulnerable configuration" for test purposes: remote management services enabled/exposed.
    # The advisory recommends restricting CLI and web-based management interfaces; thus, if these
    # services appear enabled, treat as vulnerable exposure.
    mgmt_indicators = [
        "web-server", "web server", "https", "http",
        "mgmt", "management",
        "ssh", "telnet",
        "api", "rest", "netconf",
        "papi",
    ]
    mgmt_enabled = any(ind in mgmt_cfg for ind in mgmt_indicators) and any(
        kw in mgmt_cfg for kw in ["enable", "enabled", "on", "true"]
    )

    assert not mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37144 (Aruba/HPE ArubaOS). "
        "The device appears to be running an affected AOS-10/AOS-8 version per HPESBNW04957 "
        "and has remote management services enabled (web/CLI/API), increasing exposure to an "
        "authenticated arbitrary file download via the low-level interface library. "
        f"Advisory: {advisory_url}"
    )