from comfy import high


@high(
    name="rule_cve202537143",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include web|https|http|mgmt|management|ui",
        show_mgmt_acl="show configuration | include mgmt|management|web|https|http|acl|access",
    ),
)
def rule_cve202537143(configuration, commands, device, devices):
    """
    CVE-2025-37143: Authenticated arbitrary file download vulnerability in the web-based
    management interface of AOS-10 GW and AOS-8 Controller/Mobility Conductor.

    This rule flags devices that:
      1) Run an affected (vulnerable) AOS-10/AOS-8 version per HPESBNW04957, AND
      2) Have the web-based management interface enabled/exposed (HTTP/HTTPS management UI).
    """
    version_output = (commands.show_version or "").lower()

    def _extract_version(text: str):
        # Common Aruba outputs include "ArubaOS version X.Y.Z.W" or "AOS-10.x.x.x"
        import re

        m = re.search(r"\bversion\s+(\d+\.\d+\.\d+\.\d+)\b", text, re.IGNORECASE)
        if m:
            return m.group(1)
        m = re.search(r"\b(aos-?\s*)?(\d+\.\d+\.\d+\.\d+)\b", text, re.IGNORECASE)
        if m:
            return m.group(2)
        return None

    def _ver_tuple(v: str):
        try:
            return tuple(int(x) for x in v.split("."))
        except Exception:
            return None

    current_version = _extract_version(commands.show_version or "")
    if not current_version:
        # If we cannot determine version, do not assert vulnerability.
        return

    vt = _ver_tuple(current_version)
    if not vt:
        return

    # Vulnerable ranges from HPESBNW04957:
    # AOS-10.7.x.x: 10.7.2.0 and below (fixed 10.7.2.1+)
    # AOS-10.4.x.x: 10.4.1.8 and below (fixed 10.4.1.9+)
    # AOS-8.13.x.x: 8.13.0.1 and below (fixed 8.13.1.0+)
    # AOS-8.12.x.x: 8.12.0.5 and below (fixed 8.12.0.6+)
    # AOS-8.10.x.x: 8.10.0.18 and below (fixed 8.10.0.19+)
    vulnerable = False

    # AOS-10.7 branch
    if vt[:2] == (10, 7):
        vulnerable = vt <= (10, 7, 2, 0)
    # AOS-10.4 branch
    elif vt[:2] == (10, 4):
        vulnerable = vt <= (10, 4, 1, 8)
    # AOS-8.13 branch
    elif vt[:2] == (8, 13):
        vulnerable = vt <= (8, 13, 0, 1)
    # AOS-8.12 branch
    elif vt[:2] == (8, 12):
        vulnerable = vt <= (8, 12, 0, 5)
    # AOS-8.10 branch
    elif vt[:2] == (8, 10):
        vulnerable = vt <= (8, 10, 0, 18)
    else:
        vulnerable = False

    if not vulnerable:
        return

    # Configuration check: web-based management interface enabled/exposed.
    # Advisory indicates the issue is in the web-based management interface; if it is disabled,
    # the attack surface is reduced/removed.
    mgmt_services = (commands.show_mgmt_services or "").lower()
    mgmt_acl = (commands.show_mgmt_acl or "").lower()
    combined = "\n".join([mgmt_services, mgmt_acl])

    web_mgmt_enabled = any(
        token in combined
        for token in [
            "web",  # generic
            "webui",
            "web-ui",
            "web management",
            "management ui",
            "http",
            "https",
            "ssl",
            "web-server",
            "web server",
        ]
    ) and not any(
        token in combined
        for token in [
            "no web",
            "web disabled",
            "disable web",
            "no http",
            "http disabled",
            "no https",
            "https disabled",
            "web-server disable",
            "web server disable",
        ]
    )

    # If we cannot find any indication, be conservative and do not fail.
    if not (mgmt_services.strip() or mgmt_acl.strip()):
        return

    assert not web_mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37143 (Aruba/HPE ArubaOS). "
        f"It is running an affected version ({current_version}) and appears to have the "
        "web-based management interface (HTTP/HTTPS) enabled, which may allow an authenticated "
        "malicious actor to download arbitrary files via carefully constructed requests. "
        "Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04957"
    )