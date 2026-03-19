from comfy import high

@high(
    name='rule_cve202537173',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_webmgmt='show configuration | include web-server',
        show_mgmt_acl='show configuration | include mgmt-user',
    ),
)
def rule_cve202537173(configuration, commands, device, devices):
    """
    CVE-2025-37173: Improper input handling vulnerability in an authenticated
    configuration API endpoint in the web-based management interface (AOS-8/AOS-10).

    Advisory: HPESBNW04987 rev.2
    """
    version_output = (commands.show_version or "").strip()

    # Affected versions per advisory:
    # AOS-10.7.x.x: 10.7.2.1 and below (fixed in 10.7.2.2+)
    # AOS-10.4.x.x: 10.4.1.9 and below (fixed in 10.4.1.10+)
    # AOS-8.13.x.x: 8.13.1.0 and below (fixed in 8.13.1.1+)
    # AOS-8.10.x.x: 8.10.0.20 and below (fixed in 8.10.0.21+)
    #
    # Note: EoM branches are affected but not fixed; we treat them as vulnerable if detected.
    vulnerable_markers = [
        # AOS-10.7 vulnerable
        "10.7.2.1", "10.7.2.0",
        # AOS-10.4 vulnerable
        "10.4.1.9", "10.4.1.8", "10.4.1.7", "10.4.1.6", "10.4.1.5",
        "10.4.1.4", "10.4.1.3", "10.4.1.2", "10.4.1.1", "10.4.1.0",
        # AOS-8.13 vulnerable
        "8.13.1.0",
        # AOS-8.10 vulnerable
        "8.10.0.20", "8.10.0.19", "8.10.0.18", "8.10.0.17", "8.10.0.16",
        "8.10.0.15", "8.10.0.14", "8.10.0.13", "8.10.0.12", "8.10.0.11",
        "8.10.0.10", "8.10.0.9", "8.10.0.8", "8.10.0.7", "8.10.0.6",
        "8.10.0.5", "8.10.0.4", "8.10.0.3", "8.10.0.2", "8.10.0.1",
        "8.10.0.0",
        # EoM branches (all affected per advisory; include common markers)
        "10.6.", "10.5.", "10.3.",
        "8.12.", "8.11.", "8.9.", "8.8.", "8.7.", "8.6.",
        "6.5.4.",
    ]

    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        return

    # Configuration exposure: vulnerability is in the web-based management interface and
    # requires authenticated access. We treat "web-server enabled" as the vulnerable
    # configuration, and "mgmt-user" ACL restriction as a mitigating/safe configuration.
    webmgmt_cfg_raw = (commands.show_webmgmt or "").lower()
    webmgmt_cfg = "\n".join(
        line for line in webmgmt_cfg_raw.splitlines()
        if not line.strip().startswith("#") and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )
    mgmt_acl_raw = (commands.show_mgmt_acl or "").lower()
    mgmt_acl_cfg = "\n".join(
        line for line in mgmt_acl_raw.splitlines()
        if not line.strip().startswith("#") and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )

    web_ui_enabled = ("web-server" in webmgmt_cfg and "enable" in webmgmt_cfg) or ("web-server enable" in webmgmt_cfg)
    mgmt_acl_restricted = "mgmt-user" in mgmt_acl_cfg  # presence indicates management access is restricted by ACL

    # Vulnerable scenario: vulnerable version + web UI enabled + no mgmt ACL restriction
    is_vulnerable = version_vulnerable and web_ui_enabled and not mgmt_acl_restricted

    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbnw04987en_us"

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37173 (Improper Input Handling in authenticated "
        f"configuration API endpoint of the web-based management interface). The device appears to be running "
        f"an affected ArubaOS version and has the web-based management interface enabled without a management "
        f"ACL restriction (mgmt-user). Upgrade to a fixed release (AOS-10 10.7.2.2+/10.4.1.10+ or AOS-8 "
        f"8.13.1.1+/8.10.0.21+) and/or restrict management access. Advisory: {advisory_url}"
    )