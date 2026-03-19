from comfy import high


@high(
    name="rule_cve202537132",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include (web|https|http|mgmt|management|svc|service)",
        show_mgmt_acl="show configuration | include (mgmt|management) (acl|access-list|allowlist|whitelist|restrict)",
    ),
)
def rule_cve202537132(configuration, commands, device, devices):
    """
    CVE-2025-37132: Authenticated RCE via arbitrary file write in the web-based management interface
    affecting Aruba/HPE AOS-10 Gateways and AOS-8 Controllers/Mobility Conductors.

    This rule is a configuration-aware exposure check:
      - If the device runs an affected (vulnerable) software version AND
      - the web-based management interface appears enabled/exposed (no clear restriction),
    then the device is considered vulnerable/exposed.

    Advisory: HPESBNW04957 rev.1
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = (commands.show_version or "").strip()

    # Helper: parse "ArubaOS version X.Y.Z.W" or similar
    def _extract_version(text: str):
        import re

        m = re.search(r"\bversion\s+(\d+\.\d+\.\d+\.\d+)\b", text, re.IGNORECASE)
        return m.group(1) if m else None

    def _ver_tuple(v: str):
        return tuple(int(x) for x in v.split("."))

    v = _extract_version(version_output)
    if not v:
        # If we cannot determine version, do not assert vulnerability.
        return

    vt = _ver_tuple(v)

    # Vulnerable versions per advisory:
    # AOS-10.7.x.x: 10.7.2.0 and below (fixed in 10.7.2.1+)
    # AOS-10.4.x.x: 10.4.1.8 and below (fixed in 10.4.1.9+)
    # AOS-8.13.x.x: 8.13.0.1 and below (fixed in 8.13.1.0+)
    # AOS-8.12.x.x: 8.12.0.5 and below (fixed in 8.12.0.6+)
    # AOS-8.10.x.x: 8.10.0.18 and below (fixed in 8.10.0.19+)
    # EoM branches listed as affected (no fix): AOS-10.6/10.5/10.3, AOS-8.11/8.9/8.8/8.7/8.6, AOS-6.5.4
    vulnerable = False

    # AOS-10
    if vt[0] == 10:
        if vt[1] == 7:
            vulnerable = vt <= _ver_tuple("10.7.2.0")
        elif vt[1] == 4:
            vulnerable = vt <= _ver_tuple("10.4.1.8")
        elif vt[1] in (6, 5, 3):
            vulnerable = True

    # AOS-8 / AOS-6.5.4
    if vt[0] == 8:
        if vt[1] == 13:
            vulnerable = vt <= _ver_tuple("8.13.0.1")
        elif vt[1] == 12:
            vulnerable = vt <= _ver_tuple("8.12.0.5")
        elif vt[1] == 10:
            vulnerable = vt <= _ver_tuple("8.10.0.18")
        elif vt[1] in (11, 9, 8, 7, 6):
            vulnerable = True
    if vt[0] == 6 and vt[1] == 5 and vt[2] == 4:
        vulnerable = True

    if not vulnerable:
        return

    raw_mgmt_services = (commands.show_mgmt_services or "").lower()
    raw_mgmt_acl = (commands.show_mgmt_acl or "").lower()

    def _active_lines(text):
        """Return only positive configuration lines (skip comments and no-X negations)."""
        result = []
        for line in text.splitlines():
            s = line.strip()
            if not s or s.startswith("#") or s.startswith("!") or s.startswith("no "):
                continue
            result.append(s)
        return "\n".join(result)

    mgmt_services = _active_lines(raw_mgmt_services)
    mgmt_acl = _active_lines(raw_mgmt_acl)

    # Configuration exposure heuristic:
    # - Vulnerability is in the web-based management interface; if web/https/http mgmt is enabled,
    #   and there is no sign of restriction (mgmt ACL / allowlist / restricted mgmt), treat as exposed.
    web_enabled = any(
        token in mgmt_services
        for token in (
            "web",
            "webui",
            "web-ui",
            "web-based",
            "https",
            "http",
            "management interface",
            "mgmt",
        )
    ) and not any(token in mgmt_services for token in ("disable", "disabled", "shutdown", "off"))

    # "Safe" configuration: explicit restriction/segmentation/ACL hints in config output
    restricted = any(
        token in mgmt_acl
        for token in (
            "mgmt acl",
            "management acl",
            "access-list",
            "acl",
            "allowlist",
            "whitelist",
            "restrict",
            "restricted",
            "permit",
            "deny",
            "source",
            "trusted",
            "vlan",
            "l2",
            "firewall",
        )
    ) or any(token in mgmt_services for token in ("mgmt-only", "management-only", "restricted"))

    # If web mgmt is enabled and not clearly restricted, fail.
    if web_enabled and not restricted:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-37132 (Aruba/HPE ArubaOS). "
            f"Detected vulnerable software version '{v}' and web-based management interface appears enabled/exposed "
            f"without clear management access restrictions. Successful exploitation could allow an authenticated actor "
            f"to perform arbitrary file write leading to arbitrary command execution. "
            f"Advisory: {advisory_url}"
        )

    # Otherwise, pass (either web mgmt not enabled, or it appears restricted)
    assert True