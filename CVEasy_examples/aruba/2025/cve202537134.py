from comfy import high

@high(
    name='rule_cve202537134',
    platform=['aruba_os'],
    commands=dict(
        show_version='show version',
        show_mgmt_access='show mgmt-user',
        show_webserver='show configuration | include web-server',
        show_http='show configuration | include http',
        show_https='show configuration | include https',
    ),
)
def rule_cve202537134(configuration, commands, device, devices):
    """
    CVE-2025-37134: Authenticated command injection vulnerability in a low-level interface
    library affecting AOS-10 GW and AOS-8 Controller/Mobility Conductor web-based management
    interface. Successful exploitation could allow an authenticated malicious actor to execute
    arbitrary commands as a privileged user on the underlying operating system.

    This rule flags devices that:
      1) Run an affected ArubaOS/AOS version per HPESBNW04957, AND
      2) Have the web-based management interface enabled/exposed (HTTP/HTTPS/web-server enabled),
         AND
      3) Have at least one management user configured (indicating authenticated access is possible).
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").strip()

    # Helper: parse "ArubaOS version X.Y.Z.W" or "AOS-10 version X.Y.Z.W"
    def _extract_version(text: str):
        import re
        m = re.search(r'\bversion\s+(\d+\.\d+\.\d+\.\d+)\b', text, re.IGNORECASE)
        return m.group(1) if m else None

    ver = _extract_version(version_output)
    if not ver:
        # If we cannot determine version, do not assert vulnerability.
        return

    def _ver_tuple(v: str):
        return tuple(int(x) for x in v.split("."))

    v = _ver_tuple(ver)

    # Vulnerable versions per advisory HPESBNW04957 rev.1:
    # AOS-10.7.x.x: 10.7.2.0 and below (fixed 10.7.2.1+)
    # AOS-10.4.x.x: 10.4.1.8 and below (fixed 10.4.1.9+)
    # AOS-8.13.x.x: 8.13.0.1 and below (fixed 8.13.1.0+)
    # AOS-8.12.x.x: 8.12.0.5 and below (fixed 8.12.0.6+)
    # AOS-8.10.x.x: 8.10.0.18 and below (fixed 8.10.0.19+)
    #
    # Note: EoM branches are also affected but not patched; we treat them as vulnerable if detected.
    vulnerable = False

    # AOS-10.7 branch
    if v[0] == 10 and v[1] == 7:
        vulnerable = v <= _ver_tuple("10.7.2.0")
    # AOS-10.4 branch
    elif v[0] == 10 and v[1] == 4:
        vulnerable = v <= _ver_tuple("10.4.1.8")
    # AOS-10 other branches listed as EoM (10.6/10.5/10.3): all affected
    elif v[0] == 10 and v[1] in (6, 5, 3):
        vulnerable = True
    # AOS-8.13 branch
    elif v[0] == 8 and v[1] == 13:
        vulnerable = v <= _ver_tuple("8.13.0.1")
    # AOS-8.12 branch
    elif v[0] == 8 and v[1] == 12:
        vulnerable = v <= _ver_tuple("8.12.0.5")
    # AOS-8.10 branch
    elif v[0] == 8 and v[1] == 10:
        vulnerable = v <= _ver_tuple("8.10.0.18")
    # AOS-8 EoM branches (8.11/8.9/8.8/8.7/8.6): all affected
    elif v[0] == 8 and v[1] in (11, 9, 8, 7, 6):
        vulnerable = True
    # AOS-6.5.4.x: all affected (per advisory list)
    elif v[0] == 6 and v[1] == 5 and v[2] == 4:
        vulnerable = True

    if not vulnerable:
        return

    # Determine whether web-based management interface is enabled.
    webserver_cfg = "\n".join([
        commands.show_webserver or "",
        commands.show_http or "",
        commands.show_https or "",
    ]).lower()

    # Heuristics: treat as enabled if any of these appear.
    web_mgmt_enabled = any(
        token in webserver_cfg
        for token in (
            "web-server",
            "web server",
            "http",
            "https",
            "ssl",
        )
    ) and not any(
        token in webserver_cfg
        for token in (
            "no web-server",
            "no web server",
            "web-server disable",
            "web server disable",
            "no http",
            "no https",
            "http disable",
            "https disable",
        )
    )

    # Determine whether at least one management user exists (authenticated access prerequisite).
    mgmt_users = (commands.show_mgmt_access or "").strip().lower()
    has_mgmt_user = any(
        token in mgmt_users
        for token in (
            "mgmt-user",
            "mgmt user",
            "user",
            "username",
        )
    ) and not any(
        token in mgmt_users
        for token in (
            "no mgmt-user",
            "no mgmt user",
            "no users",
            "0 users",
            "none",
        )
    )

    is_vulnerable_state = web_mgmt_enabled and has_mgmt_user

    assert not is_vulnerable_state, (
        f"Device {device.name} is vulnerable to CVE-2025-37134 (HPESBNW04957). "
        f"Detected affected ArubaOS/AOS version {ver} with web-based management interface enabled "
        f"and management users present, which may allow authenticated command injection leading to "
        f"privileged OS command execution. Advisory: {advisory_url}"
    )