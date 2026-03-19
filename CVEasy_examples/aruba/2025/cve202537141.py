from comfy import high


@high(
    name="rule_cve202537141",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web-server|https-server|http-server|mgmt-server|management|aaa|user|local-user|tacacs|radius)",
    ),
)
def rule_cve202537141(configuration, commands, device, devices):
    """
    CVE-2025-37141: Authenticated arbitrary file download vulnerability in the CLI binary
    affecting AOS-10 Gateways and AOS-8 Controllers/Mobility Conductors.

    Successful exploitation requires an authenticated actor. This rule flags devices that:
      1) Run an affected (vulnerable) AOS-10/AOS-8 version, AND
      2) Have remote management access plausibly enabled (web/https management services present),
         indicating an exposed management plane where authenticated access could be obtained/used.

    Advisory: HPESBNW04957 rev.1
    """
    version_output = (commands.show_version or "").lower()
    mgmt_output = (commands.show_mgmt_services or "").lower()

    def _extract_version(text: str):
        # Common Aruba outputs include:
        # "ArubaOS version 8.12.0.5"
        # "ArubaOS version 10.7.2.0"
        # "AOS-10.7.2.0" etc.
        import re

        m = re.search(r"\b(?:arubaos\s+version|aos-)\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", text, re.I)
        if m:
            return m.group(1)
        m = re.search(r"\b([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\b", text)
        return m.group(1) if m else None

    def _ver_tuple(v: str):
        return tuple(int(x) for x in v.split("."))

    v = _extract_version(commands.show_version or "")
    if not v:
        return

    vt = _ver_tuple(v)

    # Vulnerable versions per advisory (affected at and below):
    # AOS-10.7.x.x: 10.7.2.0 and below (within 10.7 branch)
    # AOS-10.4.x.x: 10.4.1.8 and below (within 10.4 branch)
    # AOS-8.13.x.x: 8.13.0.1 and below (within 8.13 branch)
    # AOS-8.12.x.x: 8.12.0.5 and below (within 8.12 branch)
    # AOS-8.10.x.x: 8.10.0.18 and below (within 8.10 branch)
    vulnerable = False

    # AOS-10.7.x.x
    if vt[:2] == (10, 7) and vt <= _ver_tuple("10.7.2.0"):
        vulnerable = True
    # AOS-10.4.x.x
    elif vt[:2] == (10, 4) and vt <= _ver_tuple("10.4.1.8"):
        vulnerable = True
    # AOS-8.13.x.x
    elif vt[:2] == (8, 13) and vt <= _ver_tuple("8.13.0.1"):
        vulnerable = True
    # AOS-8.12.x.x
    elif vt[:2] == (8, 12) and vt <= _ver_tuple("8.12.0.5"):
        vulnerable = True
    # AOS-8.10.x.x
    elif vt[:2] == (8, 10) and vt <= _ver_tuple("8.10.0.18"):
        vulnerable = True

    if not vulnerable:
        return

    # Configuration / exposure heuristic:
    # CVE requires authenticated access to management interfaces (CLI binary used by web-based mgmt).
    # We treat presence of web/https management services as "vulnerable configuration" for testing.
    mgmt_enabled_indicators = [
        "web-server",
        "https-server",
        "http-server",
        "mgmt-server",
        "webui",
        "web ui",
        "management",
    ]
    mgmt_lines = [
        line for line in mgmt_output.splitlines()
        if not line.strip().startswith("no ") and not line.strip().startswith("!")
        and not line.strip().startswith("#")
    ]
    mgmt_output_filtered = "\n".join(mgmt_lines)
    mgmt_enabled = any(ind in mgmt_output_filtered for ind in mgmt_enabled_indicators)

    # If management services are not indicated, consider it a "safe configuration" scenario for this test.
    if not mgmt_enabled:
        return

    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    assert False, (
        f"Device {device.name} is vulnerable to CVE-2025-37141 (Authenticated Arbitrary File Download) "
        f"because it is running an affected ArubaOS/AOS version ({v}) and management services appear enabled "
        f"(web/https management indicators found in configuration output). An authenticated attacker could "
        f"potentially download arbitrary files via carefully constructed exploits in the CLI binary. "
        f"Advisory: {advisory_url}"
    )