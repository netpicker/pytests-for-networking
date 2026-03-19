from comfy import high


@high(
    name="rule_cve202537139",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_access="show mgmt-user",
        show_services="show configuration | include (web-server|https-server|http-server|ssh|telnet|netconf|rest|api|papi|mgmt|management)",
    ),
)
def rule_cve202537139(configuration, commands, device, devices):
    """
    CVE-2025-37139 (HPESBNW04957 rev.1)

    A vulnerability in an AOS firmware binary allows an authenticated malicious actor
    to permanently delete necessary boot information, potentially rendering the system
    unbootable (hardware replacement required).

    Practical exposure requires:
      1) A vulnerable AOS version, AND
      2) A management plane that allows authenticated access (e.g., mgmt users present and
         remote management services enabled).

    This rule flags devices that are on affected versions AND appear to have remote
    management access enabled.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").lower()

    # Determine if the device is running an affected branch/version per advisory.
    # Affected (supported) versions:
    # - AOS-10.7.x.x: 10.7.2.0 and below (fixed in 10.7.2.1+)
    # - AOS-10.4.x.x: 10.4.1.8 and below (fixed in 10.4.1.9+)
    # - AOS-8.13.x.x: 8.13.0.1 and below (fixed in 8.13.1.0+)
    # - AOS-8.12.x.x: 8.12.0.5 and below (fixed in 8.12.0.6+)
    # - AOS-8.10.x.x: 8.10.0.18 and below (fixed in 8.10.0.19+)
    #
    # Additionally, the advisory states EoM branches are affected (all versions) but not patched:
    # AOS-10.6/10.5/10.3, AOS-8.11/8.9/8.8/8.7/8.6, AOS-6.5.4
    vulnerable_versions_substrings = [
        # AOS-10.7 affected up to 10.7.2.0
        "10.7.2.0",
        "10.7.1.",
        "10.7.0.",
        # AOS-10.4 affected up to 10.4.1.8
        "10.4.1.8",
        "10.4.1.7",
        "10.4.1.6",
        "10.4.1.5",
        "10.4.1.4",
        "10.4.1.3",
        "10.4.1.2",
        "10.4.1.1",
        "10.4.1.0",
        "10.4.0.",
        # AOS-8.13 affected up to 8.13.0.1
        "8.13.0.1",
        "8.13.0.0",
        # AOS-8.12 affected up to 8.12.0.5
        "8.12.0.5",
        "8.12.0.4",
        "8.12.0.3",
        "8.12.0.2",
        "8.12.0.1",
        "8.12.0.0",
        # AOS-8.10 affected up to 8.10.0.18
        "8.10.0.18",
        "8.10.0.17",
        "8.10.0.16",
        "8.10.0.15",
        "8.10.0.14",
        "8.10.0.13",
        "8.10.0.12",
        "8.10.0.11",
        "8.10.0.10",
        "8.10.0.9",
        "8.10.0.8",
        "8.10.0.7",
        "8.10.0.6",
        "8.10.0.5",
        "8.10.0.4",
        "8.10.0.3",
        "8.10.0.2",
        "8.10.0.1",
        "8.10.0.0",
        # EoM branches (all versions affected)
        "10.6.",
        "10.5.",
        "10.3.",
        "8.11.",
        "8.9.",
        "8.8.",
        "8.7.",
        "8.6.",
        "6.5.4.",
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_versions_substrings)
    if not version_vulnerable:
        return

    # Configuration/exposure checks:
    # - Presence of management users indicates authenticated access is possible.
    # - Enabled remote management services increase likelihood of remote authenticated access.
    mgmt_users_output = (commands.show_mgmt_access or "").lower()
    services_output = (commands.show_services or "").lower()

    # Heuristic: if any mgmt-user exists (common output includes usernames/roles),
    # treat as "authenticated access exists".
    has_mgmt_user = any(
        token in mgmt_users_output
        for token in [
            "mgmt-user",
            "username",
            "user ",
            "role",
            "admin",
        ]
    ) and ("no mgmt-user" not in mgmt_users_output)

    # Heuristic: remote management services enabled
    remote_mgmt_enabled = any(
        kw in services_output
        for kw in [
            "web-server",
            "https-server",
            "http-server",
            "ssh",
            "telnet",
            "netconf",
            "rest",
            "api",
            "papi enabled",
            "papi",
        ]
    ) and not any(
        kw in services_output
        for kw in [
            "web-server disable",
            "https-server disable",
            "http-server disable",
            "ssh disable",
            "telnet disable",
            "netconf disable",
            "rest disable",
            "api disable",
            "papi disabled",
        ]
    )

    config_vulnerable = has_mgmt_user and remote_mgmt_enabled

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37139. "
        "The device appears to be running an affected ArubaOS/AOS version and has "
        "authenticated management access with remote management services enabled, "
        "which increases exposure to an authenticated actor permanently deleting "
        "necessary boot information (potentially rendering the system unbootable). "
        f"Advisory: {advisory_url}"
    )