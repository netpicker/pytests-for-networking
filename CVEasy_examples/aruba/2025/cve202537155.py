from comfy import high


@high(
    name="rule_cve202537155",
    platform=["aruba_aoscx"],
    commands=dict(
        show_version="show version",
        show_ssh="show running-config | include ^ssh|^no ssh|^ssh server|^ssh vrf|^ssh (ciphers|macs|kex)|^management",
        show_users="show running-config | include ^user|^username|^aaa|^role|^class",
    ),
)
def rule_cve202537155(configuration, commands, device, devices):
    """
    CVE-2025-37155: Authenticated privilege escalation in the SSH restricted shell interface
    of AOS-CX network management services allowing read-only users to gain administrator access.

    Advisory: HPESBNW04888 rev.1 - HPE Aruba Networking AOS-CX Multiple Vulnerabilities
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04888en_us"

    version_output = (commands.show_version or "").strip()

    # Determine installed AOS-CX version (best-effort parsing)
    import re

    m = re.search(r"\b(\d+)\.(\d+)\.(\d+)\b", version_output)
    if not m:
        # If we cannot determine version, do not assert vulnerability.
        return

    major, minor, patch = map(int, m.groups())

    # Vulnerable versions per advisory:
    # 10.16.1000 and below
    # 10.15.1020 and below
    # 10.14.1050 and below
    # 10.13.1090 and below
    # 10.10.1160 and below
    vulnerable = False
    if major == 10 and minor == 16 and patch <= 1000:
        vulnerable = True
    elif major == 10 and minor == 15 and patch <= 1020:
        vulnerable = True
    elif major == 10 and minor == 14 and patch <= 1050:
        vulnerable = True
    elif major == 10 and minor == 13 and patch <= 1090:
        vulnerable = True
    elif major == 10 and minor == 10 and patch <= 1160:
        vulnerable = True

    if not vulnerable:
        return

    # Configuration condition (best-effort):
    # The issue is in the SSH restricted shell interface of network management services.
    # Treat device as "exposed" if SSH server is enabled (not explicitly disabled).
    ssh_cfg = (commands.show_ssh or "").lower()
    ssh_enabled = True
    if "no ssh" in ssh_cfg or "no ssh server" in ssh_cfg:
        ssh_enabled = False

    # Also require presence of at least one local read-only style user/role indicator.
    # (We cannot reliably validate role semantics from config alone; this is a heuristic
    # to avoid flagging devices with no read-only accounts configured.)
    users_cfg = (commands.show_users or "").lower()
    has_readonly_user_hint = any(
        token in users_cfg
        for token in [
            "role read-only",
            "role readonly",
            "read-only",
            "readonly",
            "operator",
            "auditor",
        ]
    )

    config_vulnerable = ssh_enabled and has_readonly_user_hint

    assert not config_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-37155 (AOS-CX SSH restricted shell "
        f"improper access control). Detected vulnerable AOS-CX version in 'show version' "
        f"({major}.{minor}.{patch}) with SSH management enabled and indications of a read-only "
        f"user/role configured. An authenticated read-only user may be able to gain administrator "
        f"access. Upgrade to a fixed release (10.16.1001+, 10.15.1030+, 10.14.1060+, 10.13.1101+, "
        f"10.10.1170+) and restrict management access as recommended. Advisory: {advisory_url}"
    )