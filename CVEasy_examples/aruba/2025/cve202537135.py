from comfy import high


@high(
    name="rule_cve202537135",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_services="show configuration | include \"(ssh|telnet|https|http|web-server|mgmt|management)\"",
    ),
)
def rule_cve202537135(configuration, commands, device, devices):
    """
    CVE-2025-37135: Authenticated arbitrary file deletion in the AOS-8 Controller/Mobility Conductor CLI.

    This rule flags devices that:
      1) Run an affected AOS-8 version (per HPESBNW04957), AND
      2) Expose remote management access paths that allow authenticated remote CLI access
         (e.g., SSH/Telnet or web management which can provide CLI access).

    Note: The advisory states exploitation requires an authenticated remote actor. Therefore,
    if remote management access is not enabled/exposed, risk is reduced.
    """
    version_output = (commands.show_version or "").lower()

    # Affected AOS-8 versions (inclusive "and below" per advisory):
    # - 8.13.0.1 and below
    # - 8.12.0.5 and below
    # - 8.10.0.18 and below
    # EoM branches are also affected (8.11.x, 8.9.x, 8.8.x, 8.7.x, 8.6.x, 6.5.4.x all)
    vulnerable_markers = [
        # 8.13.x
        "8.13.0.1",
        "8.13.0.0",
        # 8.12.x
        "8.12.0.5",
        "8.12.0.4",
        "8.12.0.3",
        "8.12.0.2",
        "8.12.0.1",
        "8.12.0.0",
        # 8.11.x (EoM, all affected)
        "8.11.",
        # 8.10.x up to .18
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
        # 8.9.x and below (EoM, all affected)
        "8.9.",
        "8.8.",
        "8.7.",
        "8.6.",
        "6.5.4.",
    ]

    version_vulnerable = any(m in version_output for m in vulnerable_markers)
    if not version_vulnerable:
        return True

    raw_mgmt = (commands.show_mgmt_services or "").lower()
    # Filter comment and negation lines to avoid false positives (e.g. "no ssh")
    mgmt_cfg = "\n".join(
        line for line in raw_mgmt.splitlines()
        if line.strip() and not line.strip().startswith("#")
        and not line.strip().startswith("!")
        and not line.strip().startswith("no ")
    )

    # "Authenticated remote" implies some remote management plane is reachable.
    # We treat SSH/Telnet and web management as vulnerable exposure paths.
    remote_cli_exposed = any(
        token in mgmt_cfg
        for token in [
            "ssh",
            "telnet",
            "web-server",
            "https",
            "http",
            "management",
            "mgmt",
        ]
    )

    assert not remote_cli_exposed, (
        f"Device {device.name} is vulnerable to CVE-2025-37135 (Aruba/HPE ArubaOS AOS-8 CLI arbitrary file deletion). "
        f"Detected an affected AOS-8 version from 'show version' output and remote management/CLI exposure in configuration, "
        f"which could allow an authenticated remote actor to delete arbitrary files on the system. "
        f"Upgrade to a fixed release (AOS-8.13.1.0+, 8.12.0.6+, or 8.10.0.19+) and restrict management access per guidance. "
        f"Advisory: https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"
    )

    return True