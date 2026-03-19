from comfy import high


@high(
    name="rule_cve202537176",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_upgrade_cfg="show configuration | include upgrade",
        show_webui_cfg="show configuration | include web-server",
    ),
)
def rule_cve202537176(configuration, commands, device, devices):
    """
    CVE-2025-37176: Authenticated command injection in an AOS-8 internal workflow.
    An authenticated privileged user can alter a package header to inject shell commands,
    potentially affecting execution of internal operations.

    This rule is a configuration + version exposure check:
      - Vulnerable if running impacted AOS-8 versions AND software/package upgrade workflow is enabled/usable.
      - Non-vulnerable if running fixed AOS-8 versions, or not AOS-8, or upgrade mechanism is disabled/restricted.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbnw04987en_us"

    version_output = (commands.show_version or "").lower()

    # Determine if device is AOS-8 and extract a best-effort version string presence check.
    is_aos8 = "arubaos" in version_output and "version" in version_output and " 8." in version_output

    # Fixed versions per advisory:
    # - AOS-8.13.x.x: 8.13.1.1 and above
    # - AOS-8.10.x.x: 8.10.0.21 and above
    #
    # Impacted versions per advisory:
    # - AOS-8.13.1.0 and below
    # - AOS-8.10.0.20 and below
    # - All EoM AOS-8 branches listed (8.12/8.11/8.9/8.8/8.7/8.6/6.5.4)
    vulnerable_markers = [
        # AOS-8.13 impacted
        "8.13.1.0",
        "8.13.0.",
        "8.13.0",
        # AOS-8.10 impacted up to .20
        "8.10.0.20",
        "8.10.0.19",
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
        # EoM branches (all affected)
        "8.12.",
        "8.11.",
        "8.9.",
        "8.8.",
        "8.7.",
        "8.6.",
        "6.5.4.",
    ]
    fixed_markers = [
        "8.13.1.1",
        "8.13.1.2",
        "8.13.1.3",
        "8.13.1.4",
        "8.13.1.5",
        "8.10.0.21",
        "8.10.0.22",
        "8.10.0.23",
        "8.10.0.24",
        "8.10.0.25",
    ]

    # If not AOS-8, not applicable for this CVE per advisory.
    if not is_aos8:
        return

    # If clearly fixed, not vulnerable.
    if any(m in version_output for m in fixed_markers):
        return

    # If we cannot match a vulnerable marker, be conservative and do not flag.
    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        return

    # Configuration exposure:
    # The issue is in an internal package workflow; practical exposure is when upgrade/package install
    # mechanisms are enabled/available to privileged users. We approximate this by checking for
    # upgrade-related configuration and whether the web server (WebUI) is enabled (common path to
    # upload/install packages/firmware in managed environments).
    upgrade_cfg = (commands.show_upgrade_cfg or "").lower()
    webui_cfg = (commands.show_webui_cfg or "").lower()

    # Heuristics for "upgrade mechanism enabled/usable"
    upgrade_enabled = any(
        token in upgrade_cfg
        for token in [
            "upgrade",
            "image",
            "firmware",
            "allow-upgrade",
            "auto-upgrade",
            "download",
        ]
    )

    webui_enabled = any(
        token in webui_cfg
        for token in [
            "web-server",
            "webserver",
            "https",
            "http",
            "enable",
        ]
    ) and not any(token in webui_cfg for token in ["disable", "shutdown", "no web-server", "no webserver"])

    config_vulnerable = upgrade_enabled and webui_enabled

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37176 (AOS-8 authenticated command injection "
        f"in an internal package workflow). The device appears to be running an impacted AOS-8 version "
        f"and has upgrade/package workflow exposure (upgrade-related configuration present and WebUI enabled), "
        f"which may allow a privileged authenticated user to alter a package header to inject shell commands. "
        f"Upgrade to a fixed release (AOS-8.13.1.1+ or AOS-8.10.0.21+) and restrict management interfaces as per advisory. "
        f"Advisory: {advisory_url}"
    )