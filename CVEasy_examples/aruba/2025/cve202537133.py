from comfy import high


@high(
    name="rule_cve202537133",
    platform=["aruba_os"],
    commands=dict(
        show_version="show version",
        show_mgmt_access="show running-config | include (web-server|https-server|http-server|mgmt|management|aaa|user|local-user|tacacs|radius|ssh|telnet)",
    ),
)
def rule_cve202537133(configuration, commands, device, devices):
    """
    CVE-2025-37133: Authenticated command injection vulnerability exists in the CLI binary
    of an AOS-8 Controller/Mobility Conductor operating system. Successful exploitation
    could allow an authenticated malicious actor to execute arbitrary commands as a
    privileged user on the underlying operating system.

    This rule is a configuration-aware exposure check:
      - Version must be within affected AOS-8 ranges per advisory.
      - Management access (CLI/Web UI) must be enabled/exposed (i.e., at least one management
        service is configured/enabled), because exploitation requires authenticated access.
    """
    advisory_url = "https://support.hpe.com/hpesc/public/docDisplay?docId=hpesbnw04957en_us"

    version_output = commands.show_version or ""
    raw_mgmt = commands.show_mgmt_access or ""
    # Filter out comment lines so keywords in comments don't trigger false positives
    mgmt_output = "\n".join(
        line for line in raw_mgmt.splitlines()
        if line.strip() and not line.strip().startswith("#")
        and not line.strip().startswith("!")
    )

    # Affected AOS-8 versions (inclusive) per HPESBNW04957:
    # 8.13.0.1 and below, 8.12.0.5 and below, 8.10.0.18 and below
    # (EoM branches are also affected but not enumerated here; this rule focuses on the
    # explicitly listed supported vulnerable trains.)
    vulnerable_versions = [
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
        # 8.10.x
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
    ]

    version_vulnerable = any(v in version_output for v in vulnerable_versions)
    if not version_vulnerable:
        return

    # Configuration exposure heuristic:
    # If any management plane service/auth is present, treat as "management enabled/exposed".
    # (CVE requires authenticated access via CLI binary; if management interfaces are disabled,
    # exposure is reduced.)
    mgmt_indicators = [
        "web-server",
        "https-server",
        "http-server",
        "mgmt",
        "management",
        "ssh",
        "telnet",
        "aaa",
        "user",
        "local-user",
        "tacacs",
        "radius",
    ]
    mgmt_enabled = any(ind in mgmt_output.lower() for ind in mgmt_indicators)

    assert not mgmt_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-37133 (Authenticated Command Injection) "
        f"because it is running an affected AOS-8 version and has management access configured/enabled "
        f"(CLI/Web management plane reachable for authenticated users). An authenticated attacker could "
        f"potentially execute arbitrary commands as a privileged user on the underlying OS. "
        f"Advisory: {advisory_url}"
    )