from comfy import high


@high(
    name="rule_cve202537171",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_webmgmt="show configuration | include web-server",
        show_mgmt_acl="show configuration | include mgmt-user|mgmt-allowlist|mgmt-acl|access-list",
    ),
)
def rule_cve202537171(configuration, commands, device, devices):
    """
    CVE-2025-37171: Authenticated command injection in the AOS-8 web-based management interface
    for Mobility Conductors. Successful exploitation allows an authenticated actor to execute
    arbitrary commands as a privileged user on the underlying OS.

    This rule is a configuration-aware exposure check:
      - Version must be in affected AOS-8 ranges per advisory.
      - Web-based management interface must be enabled/exposed (no explicit management ACL/allowlist).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04987"

    version_output = (commands.show_version or "").lower()
    web_cfg = (commands.show_webmgmt or "").lower()
    mgmt_acl_cfg = (commands.show_mgmt_acl or "").lower()

    # Affected versions (AOS-8 only) per HPESBNW04987 rev.2:
    # - AOS-8.13.x.x: 8.13.1.0 and below (fixed in 8.13.1.1+)
    # - AOS-8.10.x.x: 8.10.0.20 and below (fixed in 8.10.0.21+)
    # - EoM branches also affected: 8.12.x, 8.11.x, 8.9.x, 8.8.x, 8.7.x, 8.6.x, 6.5.4.x (all)
    vulnerable_markers = [
        # Explicitly vulnerable "and below" endpoints
        "8.13.1.0",
        "8.10.0.20",
        # EoM branches (treat any presence as vulnerable)
        "8.12.",
        "8.11.",
        "8.9.",
        "8.8.",
        "8.7.",
        "8.6.",
        "6.5.4.",
    ]

    is_aos8 = ("aos-8" in version_output) or ("arubaos version 8" in version_output) or ("version 8." in version_output)
    version_vulnerable = is_aos8 and any(m in version_output for m in vulnerable_markers)

    if not version_vulnerable:
        return

    # Web UI exposure heuristic:
    # - If web-server/http(s) is enabled AND there is no explicit management allowlist/ACL,
    #   treat as vulnerable configuration (reachable authenticated web UI).
    web_enabled = any(
        token in web_cfg
        for token in [
            "web-server",
            "web server",
            "https",
            "http",
            "mgmt-server",
            "management-server",
        ]
    ) and not any(token in web_cfg for token in ["disable", "shutdown", "no web", "no http", "no https"])

    mgmt_acl_present = any(
        token in mgmt_acl_cfg
        for token in [
            "mgmt-user",
            "mgmt-allowlist",
            "mgmt allowlist",
            "mgmt-acl",
            "mgmt acl",
            "access-list",
            "access list",
            "permit",
            "deny",
        ]
    )

    vulnerable_configuration = web_enabled and not mgmt_acl_present

    assert not vulnerable_configuration, (
        f"Device {device.name} is vulnerable to CVE-2025-37171 (Authenticated command injection) per "
        f"HPESBNW04987 rev.2. The device appears to be running an affected AOS-8 version and has the "
        f"web-based management interface enabled without an explicit management ACL/allowlist restriction, "
        f"which increases exposure to authenticated command injection leading to privileged OS command execution. "
        f"Advisory: {advisory_url}"
    )