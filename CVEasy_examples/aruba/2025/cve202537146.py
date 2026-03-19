from comfy import high


@high(
    name="rule_cve202537146",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_webmgmt_config="show configuration | include web",
        show_mgmt_acl="show configuration | include mgmt|management|access-list|acl|allowlist|whitelist",
    ),
)
def rule_cve202537146(configuration, commands, device, devices):
    """
    CVE-2025-37146: Unauthorized filesystem operations in system firmware allow Authenticated Remote Code Execution
    in the web-based management interface of network access point configuration services.

    Advisory: HPESBNW04958 rev.1
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04958en_us"

    version_output = (commands.show_version or "").lower()

    # Vulnerable versions per advisory (inclusive "and below" within listed branches)
    # AOS-10.7.x.x: 10.7.2.0 and below (fixed: 10.7.2.1+)
    # AOS-10.4.x.x: 10.4.1.7 and below (fixed: 10.4.1.9+)
    # AOS-8.13.x.x: 8.13.0.1 and below (fixed: 8.13.1.0+)
    # AOS-8.12.x.x: 8.12.0.5 and below (fixed: 8.12.0.6+)
    # AOS-8.10.x.x: 8.10.0.16 and below (fixed: 8.10.0.19+)
    vulnerable_markers = [
        # AOS-10.7.x.x
        "10.7.2.0",
        "10.7.1.",
        "10.7.0.",
        # AOS-10.4.x.x
        "10.4.1.7",
        "10.4.1.6",
        "10.4.1.5",
        "10.4.1.4",
        "10.4.1.3",
        "10.4.1.2",
        "10.4.1.1",
        "10.4.1.0",
        "10.4.0.",
        # AOS-8.13.x.x
        "8.13.0.1",
        "8.13.0.0",
        # AOS-8.12.x.x
        "8.12.0.5",
        "8.12.0.4",
        "8.12.0.3",
        "8.12.0.2",
        "8.12.0.1",
        "8.12.0.0",
        # AOS-8.10.x.x
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
        # End-of-maintenance branches called out as affected (all)
        "10.6.",
        "10.5.",
        "10.3.",
        "8.11.",
        "8.9.",
        "8.8.",
        "8.7.",
        "8.6.",
        "8.5.",
        "8.4.",
        "6.5.",
        "6.4.",
    ]

    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        return

    # Configuration condition:
    # CVE is in the web-based management interface of AP configuration services.
    # Advisory notes: "for APs with local web interfaces" and recommends restricting
    # CLI and web-based management interfaces to a dedicated L2 segment/VLAN and/or
    # controlled by firewall policies.
    #
    # We treat "web management enabled" AND "no management ACL/allowlist present"
    # as a vulnerable configuration exposure.
    web_cfg_raw = (commands.show_webmgmt_config or "").lower()
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

    web_enabled = any(
        token in web_cfg
        for token in [
            "web-server",
            "webserver",
            "web ui",
            "webui",
            "https server",
            "http server",
            "mgmt-server",
            "management-server",
            "local web",
        ]
    ) and not any(token in web_cfg for token in ["disable", "disabled", "no web", "webserver disable"])

    # Heuristic: if we see any mgmt restriction keywords, consider it "restricted"
    mgmt_restricted = any(
        token in mgmt_acl_cfg
        for token in [
            "mgmt",
            "management",
            "access-list",
            "acl",
            "allowlist",
            "whitelist",
            "permit",
            "deny",
            "source",
            "ip access-list",
        ]
    )

    vulnerable_config = web_enabled and not mgmt_restricted

    assert not vulnerable_config, (
        f"Device {device.name} is vulnerable to CVE-2025-37146 (HPESBNW04958): "
        "the device appears to be running an affected ArubaOS/AOS Instant/AP software version and has the "
        "local web-based management interface enabled without an apparent management access restriction "
        "(e.g., dedicated management VLAN/segment or ACL/allowlist). This may allow an authenticated remote "
        "attacker to achieve remote command execution on the underlying operating system. "
        f"Advisory: {advisory_url}"
    )