from comfy import high


@high(
    name="rule_cve202537172",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_webmgmt="show configuration | include web",
        show_mgmt_users="show mgmt-user",
    ),
)
def rule_cve202537172(configuration, commands, device, devices):
    """
    CVE-2025-37172: Authenticated command injection in the AOS-8 web-based management interface
    for Mobility Conductors. Exploitation requires authenticated access to the WebUI.

    This rule flags devices that:
      1) Run a vulnerable AOS-8 version (per advisory affected versions), AND
      2) Have Web-based management interface enabled/reachable (best-effort config check).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04987"

    version_output = (commands.show_version or "").lower()

    # Only AOS-8.x is impacted for CVE-2025-37172 (per advisory note).
    is_aos8 = "arubaos" in version_output and "version 8." in version_output

    # Affected AOS-8 versions:
    # - 8.13.1.0 and below
    # - 8.10.0.20 and below
    # - plus EoM branches (8.12.x, 8.11.x, 8.9.x, 8.8.x, 8.7.x, 8.6.x, 6.5.4.x) all affected
    vulnerable_markers = [
        # 8.13.x
        "version 8.13.1.0",
        "version 8.13.0.",
        # 8.12.x (EoM, all)
        "version 8.12.",
        # 8.11.x (EoM, all)
        "version 8.11.",
        # 8.10.x up to 8.10.0.20
        "version 8.10.0.0",
        "version 8.10.0.1",
        "version 8.10.0.2",
        "version 8.10.0.3",
        "version 8.10.0.4",
        "version 8.10.0.5",
        "version 8.10.0.6",
        "version 8.10.0.7",
        "version 8.10.0.8",
        "version 8.10.0.9",
        "version 8.10.0.10",
        "version 8.10.0.11",
        "version 8.10.0.12",
        "version 8.10.0.13",
        "version 8.10.0.14",
        "version 8.10.0.15",
        "version 8.10.0.16",
        "version 8.10.0.17",
        "version 8.10.0.18",
        "version 8.10.0.19",
        "version 8.10.0.20",
        # 8.9.x and below (EoM, all)
        "version 8.9.",
        "version 8.8.",
        "version 8.7.",
        "version 8.6.",
        "version 6.5.4.",
    ]

    version_vulnerable = is_aos8 and any(m in version_output for m in vulnerable_markers)

    # If not a vulnerable version, not applicable.
    if not version_vulnerable:
        assert True
        return

    # Best-effort determination of whether WebUI management is enabled.
    # ArubaOS config output varies; we treat explicit disable as safe, otherwise assume enabled.
    web_cfg = (commands.show_webmgmt or "").lower()
    mgmt_users = (commands.show_mgmt_users or "").lower()

    explicit_web_disabled = any(
        s in web_cfg
        for s in [
            "no web-server",
            "no webserver",
            "web-server disable",
            "webserver disable",
            "https disable",
            "http disable",
        ]
    )

    # If there are no management users, authenticated exploitation is less likely.
    # Treat "no entries"/empty as a mitigating (safe) configuration for this test harness.
    has_mgmt_users = not any(
        s in mgmt_users
        for s in [
            "no mgmt users",
            "no management users",
            "no entries",
            "0 entries",
            "not configured",
        ]
    ) and len(mgmt_users.strip()) > 0

    webui_enabled = not explicit_web_disabled

    configuration_vulnerable = webui_enabled and has_mgmt_users

    assert not configuration_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37172 (Authenticated Command Injection) "
        f"because it is running a vulnerable AOS-8 version and the web-based management interface "
        f"appears enabled with management users present, enabling authenticated exploitation that "
        f"could lead to arbitrary command execution as a privileged user. "
        f"Advisory: {advisory_url}"
    )