from comfy import high


@high(
    name="rule_cve202537169",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_web_mgmt="show configuration | include web",
        show_mgmt_acl="show configuration | include mgmt",
    ),
)
def rule_cve202537169(configuration, commands, device, devices):
    """
    CVE-2025-37169: Stack overflow in AOS-10 web-based management interface (Mobility Gateway).
    Successful exploitation could allow an authenticated actor to execute arbitrary code as a
    privileged user on the underlying OS.

    This rule flags devices that:
      1) Run a vulnerable AOS-10 version (per HPESBNW04987 rev.2), AND
      2) Have web-based management interface enabled/exposed by configuration.

    Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04987
    """
    version_output = commands.show_version or ""

    def _extract_aos_version(text: str):
        # Common outputs include: "ArubaOS version 10.7.2.1" or "ArubaOS 10.4.1.9"
        import re

        m = re.search(r"\b(?:ArubaOS(?:\s+version)?\s+)(\d+\.\d+\.\d+\.\d+)\b", text, re.IGNORECASE)
        return m.group(1) if m else None

    def _parse_ver(v: str):
        return tuple(int(x) for x in v.split("."))

    def _is_vulnerable_version(v: str) -> bool:
        """
        AOS-10 impacted only.
        Vulnerable:
          - 10.7.x.x: 10.7.2.1 and below
          - 10.4.x.x: 10.4.1.9 and below
        Fixed:
          - 10.7.2.2 and above
          - 10.4.1.10 and above
        """
        if not v:
            return False
        if not v.startswith("10."):
            return False

        pv = _parse_ver(v)

        # 10.7.2.1 and below (within 10.7.x.x)
        if pv[0:2] == (10, 7):
            return pv <= _parse_ver("10.7.2.1")

        # 10.4.1.9 and below (within 10.4.x.x)
        if pv[0:2] == (10, 4):
            return pv <= _parse_ver("10.4.1.9")

        # Other AOS-10 branches are either EoM (still affected but not addressed) or not listed as impacted
        # by this advisory's "Affected Software Version(s)" section; we conservatively do not flag them here.
        return False

    aos_version = _extract_aos_version(version_output)
    version_vulnerable = _is_vulnerable_version(aos_version)

    if not version_vulnerable:
        return

    web_cfg_raw = (commands.show_web_mgmt or "").lower()
    web_cfg = "\n".join(
        line for line in web_cfg_raw.splitlines()
        if not line.strip().startswith("#") and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )
    mgmt_acl_raw = (commands.show_mgmt_acl or "").lower()
    mgmt_acl_cfg = "\n".join(
        line for line in mgmt_acl_raw.splitlines()
        if not line.strip().startswith("#") and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )

    # "Vulnerable configuration" for this CVE: web-based management interface enabled and not clearly restricted.
    # We treat the following as "enabled":
    #   - "web-server enable" / "webserver enable" / "webui enable" / "https-server enable"
    # And "restricted" if we see an explicit management ACL / allowlist / restriction keyword.
    web_enabled_markers = (
        "web-server enable",
        "webserver enable",
        "webui enable",
        "https-server enable",
        "https enable",
        "http enable",
    )
    web_enabled = any(m in web_cfg for m in web_enabled_markers)

    # Heuristic: if management access is restricted by an ACL/policy, treat as safer configuration.
    restriction_markers = (
        "mgmt-access",
        "management-access",
        "mgmt acl",
        "mgmt-acl",
        "web mgmt-acl",
        "web-mgmt-acl",
        "allowlist",
        "whitelist",
        "access-list",
        "acl",
        "restrict",
        "trusted",
        "permit",
    )
    mgmt_restricted = any(m in mgmt_acl_cfg for m in restriction_markers) or any(m in web_cfg for m in restriction_markers)

    config_vulnerable = web_enabled and not mgmt_restricted

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37169: it is running a vulnerable AOS-10 version "
        f"({aos_version}) and the web-based management interface appears enabled without clear management "
        f"access restriction, which may allow an authenticated attacker to trigger a stack overflow and "
        f"execute arbitrary code as a privileged user. "
        f"Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=HPESBNW04987"
    )