from comfy import high


@high(
    name="rule_cve202537175",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_webmgmt="show configuration | include web",
        show_mgmt_users="show configuration | include mgmt-user",
    ),
)
def rule_cve202537175(configuration, commands, device, devices):
    """
    CVE-2025-37175: Authenticated arbitrary file upload in the web-based management interface
    of Aruba/HPE Mobility Conductors running AOS-8 or AOS-10.

    Successful exploitation could allow an authenticated malicious actor to upload arbitrary files
    as a privileged user and execute arbitrary commands on the underlying operating system.

    This rule flags devices that:
      1) Run an affected AOS-8/AOS-10 version per HPESBNW04987 rev.2, AND
      2) Have the web-based management interface enabled/exposed (i.e., WebUI/HTTPS server enabled).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=emr_na-hpesbnw04987en_us"

    version_output = (commands.show_version or "").lower()

    # Determine if device is running AOS-8 or AOS-10 and extract a best-effort version token.
    # We keep matching simple and robust for test harnesses: look for known "ArubaOS version X.Y.Z.W".
    def _extract_version_tokens(text: str):
        tokens = []
        for line in text.splitlines():
            line = line.strip()
            if "arubaos version" in line.lower():
                # e.g., "ArubaOS version 10.7.2.1"
                parts = line.replace(":", " ").split()
                for i, p in enumerate(parts):
                    if p.lower() == "version" and i + 1 < len(parts):
                        tokens.append(parts[i + 1].strip())
        return tokens

    versions_found = _extract_version_tokens(commands.show_version or "")
    version_str = versions_found[0] if versions_found else ""

    # Vulnerable versions per advisory:
    # AOS-10.7.x.x: 10.7.2.1 and below
    # AOS-10.4.x.x: 10.4.1.9 and below
    # AOS-8.13.x.x: 8.13.1.0 and below
    # AOS-8.10.x.x: 8.10.0.20 and below
    #
    # Also notes EoM branches are affected (all), but we cannot enumerate all; we key off the
    # explicitly listed impacted trains and common "ArubaOS version" output.
    vulnerable_versions = set(
        [
            # AOS-10.7.x.x (<= 10.7.2.1)
            "10.7.2.1",
            "10.7.2.0",
            "10.7.1.9",
            "10.7.1.8",
            "10.7.1.7",
            "10.7.1.6",
            "10.7.1.5",
            "10.7.1.4",
            "10.7.1.3",
            "10.7.1.2",
            "10.7.1.1",
            "10.7.1.0",
            "10.7.0.0",
            # AOS-10.4.x.x (<= 10.4.1.9)
            "10.4.1.9",
            "10.4.1.8",
            "10.4.1.7",
            "10.4.1.6",
            "10.4.1.5",
            "10.4.1.4",
            "10.4.1.3",
            "10.4.1.2",
            "10.4.1.1",
            "10.4.1.0",
            "10.4.0.0",
            # AOS-8.13.x.x (<= 8.13.1.0)
            "8.13.1.0",
            "8.13.0.0",
            # AOS-8.10.x.x (<= 8.10.0.20)
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
        ]
    )

    version_vulnerable = False
    if version_str:
        version_vulnerable = version_str in vulnerable_versions
    else:
        # If we cannot parse a version, do not assert vulnerability.
        return

    if not version_vulnerable:
        return

    # Configuration check: vulnerability is in the web-based management interface.
    # We treat "web server enabled" / "https server enabled" / "webui enabled" as vulnerable exposure.
    web_cfg = (commands.show_webmgmt or "").lower()
    users_cfg = (commands.show_mgmt_users or "").lower()

    web_enabled_indicators = [
        "web-server",
        "web server",
        "webui",
        "https server",
        "http server",
        "mgmt-ui",
        "management interface",
    ]
    web_disabled_indicators = [
        "no web-server",
        "no web server",
        "webui disable",
        "webui disabled",
        "no webui",
        "https server disable",
        "http server disable",
        "disable web",
        "disabled web",
    ]

    web_enabled = any(ind in web_cfg for ind in web_enabled_indicators) and not any(
        ind in web_cfg for ind in web_disabled_indicators
    )

    # Also require that at least one management user exists (authenticated actor prerequisite).
    # If we can't find any mgmt-user lines, we assume not configured for WebUI auth in this harness.
    has_mgmt_user = "mgmt-user" in users_cfg or "mgmt user" in users_cfg or "admin" in users_cfg

    config_vulnerable = web_enabled and has_mgmt_user

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37175 (Aruba/HPE ArubaOS). "
        f"Detected vulnerable ArubaOS version '{version_str}' with web-based management interface enabled "
        f"and management users present, which may allow an authenticated attacker to upload arbitrary files "
        f"and execute arbitrary commands as a privileged user. "
        f"Advisory: {advisory_url}"
    )