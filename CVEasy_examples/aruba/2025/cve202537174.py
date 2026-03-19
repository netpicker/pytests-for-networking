from comfy import high


@high(
    name="rule_cve202537174",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_web_mgmt="show configuration | include web",
    ),
)
def rule_cve202537174(configuration, commands, device, devices):
    """
    CVE-2025-37174: Authenticated arbitrary file write in the web-based management interface
    of Mobility Conductors running AOS-8 or AOS-10. Successful exploitation could allow an
    authenticated actor to create/modify arbitrary files and execute arbitrary commands as
    a privileged user.

    This rule is a configuration-based exposure check:
      - If the device runs an affected version AND the web-based management interface is enabled,
        flag as vulnerable.
      - If the device runs a fixed version, or web management is disabled/restricted, do not flag.

    Advisory: HPESBNW04987 rev.2
    """

    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04987"

    version_output = (commands.show_version or "").strip()
    web_cfg = (commands.show_web_mgmt or "").lower()

    # Determine installed version string (best-effort parsing)
    # Common outputs include: "ArubaOS version 10.4.1.9" or "ArubaOS 8.10.0.20"
    import re

    m = re.search(r"\b(?:arubaos(?:\s+version)?\s+)?(\d+\.\d+\.\d+\.\d+)\b", version_output, re.IGNORECASE)
    installed_version = m.group(1) if m else None

    def parse_ver(v):
        return tuple(int(x) for x in v.split("."))

    def in_range(v, low, high):
        """Inclusive range check: low <= v <= high"""
        pv = parse_ver(v)
        return parse_ver(low) <= pv <= parse_ver(high)

    # Vulnerable versions per advisory:
    # AOS-10.7.x.x: 10.7.2.1 and below (fixed: 10.7.2.2+)
    # AOS-10.4.x.x: 10.4.1.9 and below (fixed: 10.4.1.10+)
    # AOS-8.13.x.x: 8.13.1.0 and below (fixed: 8.13.1.1+)
    # AOS-8.10.x.x: 8.10.0.20 and below (fixed: 8.10.0.21+)
    # EoM branches listed as affected (not patched): AOS-10.6/10.5/10.3, AOS-8.12/8.11/8.9/8.8/8.7/8.6/6.5.4
    def is_vulnerable_version(v):
        if not v:
            return False

        # Patched cutoffs for maintained trains
        if in_range(v, "10.7.0.0", "10.7.2.1"):
            return True
        if in_range(v, "10.4.0.0", "10.4.1.9"):
            return True
        if in_range(v, "8.13.0.0", "8.13.1.0"):
            return True
        if in_range(v, "8.10.0.0", "8.10.0.20"):
            return True

        # EoM affected trains (treat all as vulnerable)
        if in_range(v, "10.6.0.0", "10.6.99.99"):
            return True
        if in_range(v, "10.5.0.0", "10.5.99.99"):
            return True
        if in_range(v, "10.3.0.0", "10.3.99.99"):
            return True
        if in_range(v, "8.12.0.0", "8.12.99.99"):
            return True
        if in_range(v, "8.11.0.0", "8.11.99.99"):
            return True
        if in_range(v, "8.9.0.0", "8.9.99.99"):
            return True
        if in_range(v, "8.8.0.0", "8.8.99.99"):
            return True
        if in_range(v, "8.7.0.0", "8.7.99.99"):
            return True
        if in_range(v, "8.6.0.0", "8.6.99.99"):
            return True
        if in_range(v, "6.5.4.0", "6.5.4.99"):
            return True

        return False

    version_vulnerable = is_vulnerable_version(installed_version)

    # Configuration exposure: web-based management interface enabled.
    # ArubaOS configs vary; we treat explicit enablement as exposure and explicit disablement as safe.
    # If we cannot determine, default to "enabled" only when we see clear enable keywords.
    web_enabled_markers = [
        "web-server",
        "web server",
        "webui",
        "web ui",
        "https server",
        "http server",
        "mgmt-server",
        "management server",
    ]
    web_disabled_markers = [
        "no web-server",
        "no web server",
        "web-server disable",
        "web server disable",
        "webui disable",
        "no webui",
        "no http server",
        "no https server",
        "disable web",
    ]

    web_disabled = any(x in web_cfg for x in web_disabled_markers)
    web_enabled = (not web_disabled) and any(x in web_cfg for x in web_enabled_markers)

    # If not a vulnerable version, pass.
    if not version_vulnerable:
        assert True
        return

    # If vulnerable version but web management not enabled (or explicitly disabled), pass.
    if not web_enabled:
        assert True
        return

    # Vulnerable version + web management enabled => fail.
    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37174 (Authenticated arbitrary file write) "
        f"because it is running an affected ArubaOS version"
        f"{' ' + installed_version if installed_version else ''} and has the web-based management "
        f"interface enabled, which may allow an authenticated attacker to create/modify arbitrary files "
        f"and execute arbitrary commands as a privileged user. "
        f"Upgrade to a fixed release (AOS-10 10.7.2.2+/10.4.1.10+ or AOS-8 8.13.1.1+/8.10.0.21+) and/or "
        f"disable/restrict web management access. Advisory: {advisory_url}"
    )