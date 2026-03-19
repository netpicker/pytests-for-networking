from comfy import high


@high(
    name="rule_cve202525042",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_running_config="show running-config",
        show_https_server="show running-config | include (https-server|http-server|rest|web)",
    ),
)
def rule_cve202525042(configuration, commands, device, devices):
    """
    CVE-2025-25042: Authenticated Access Control Vulnerability allows Sensitive Information
    Disclosure in AOS-CX REST Interface.

    This rule flags devices that are:
      1) Running an affected AOS-CX version branch at/below the fixed patch level, AND
      2) Have the web/REST management interface enabled (HTTPS server / REST API).

    Advisory: HPESBNW04818 rev.1
    https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04818en_us
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04818en_us"

    version_output = (commands.show_version or "").lower()

    # Affected versions (per advisory):
    # 10.15.xxxx: 10.15.1000 and below (fixed in 10.15.1001+)
    # 10.14.xxxx: 10.14.1030 and below (fixed in 10.14.1040+)
    # 10.13.xxxx: 10.13.1070 and below (fixed in 10.13.1080+)
    # 10.10.xxxx: 10.10.1140 and below (fixed in 10.10.1150+)
    #
    # Note: We match explicit vulnerable patch versions as substrings in "show version"
    # output to avoid relying on a version parser that may not exist in this framework.
    vulnerable_versions = {
        # 10.15
        "10.15.1000",
        # 10.14
        "10.14.1030",
        # 10.13
        "10.13.1070",
        # 10.10
        "10.10.1140",
    }

    version_vulnerable = any(v in version_output for v in vulnerable_versions)
    if not version_vulnerable:
        return

    # Configuration exposure condition:
    # CVE is in the REST interface; practical exposure requires the web/REST management
    # interface to be enabled/reachable. We treat "https-server" (and common web/rest
    # keywords) as enabling conditions.
    raw_cfg = ((commands.show_running_config or "") + "\n" + (commands.show_https_server or "")).lower()
    # Only consider positive configuration lines (skip comments and "no X" negations)
    cfg_lines = [
        line for line in raw_cfg.splitlines()
        if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    ]
    cfg = "\n".join(cfg_lines)

    web_mgmt_enabled = any(
        token in cfg
        for token in (
            "https-server",
            "http-server",
            "rest",
            "rest-interface",
            "web-management",
            "web ui",
        )
    )

    assert not web_mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-25042 (AOS-CX REST interface sensitive "
        f"information disclosure). The device appears to be running an affected AOS-CX version "
        f"(per HPESBNW04818) and has web/REST management enabled (e.g., https-server/rest). "
        f"An authenticated low-privilege user may be able to view sensitive information, "
        f"including encrypted credentials of other users. Upgrade to a fixed release "
        f"(10.15.1001+, 10.14.1040+, 10.13.1080+, 10.10.1150+) and restrict web management "
        f"access to a dedicated management VLAN/segment. Advisory: {advisory_url}"
    )