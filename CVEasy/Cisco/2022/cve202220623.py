from comfy import high
import re

@high(
    name='rule_cve202220623',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_bfd='show running-config | include feature bfd'
    ),
)
def rule_cve202220623(configuration, commands, device, devices):
    """
    CVE-2022-20623: BFD DoS vulnerability in Cisco NX-OS.
    Affects Nexus 9000 Series if BFD is enabled and version ≤ 7.0(3)I7(10) or ≤ 9.3(8).
    """
    platform_output = commands.show_version
    bfd_output = commands.check_bfd

    # 1. Check if device is a Nexus 9000
    is_n9k = 'Nexus 9000' in platform_output
    if not is_n9k:
        return

    # 2. Check if BFD is enabled
    bfd_enabled = 'feature bfd' in bfd_output
    if not bfd_enabled:
        return

    # 3. Extract NX-OS version
    match = re.search(r'NXOS:\s+version\s+([\w\.\(\)]+)', platform_output, re.IGNORECASE)
    if not match:
        return  # Can't extract version

    version = match.group(1)

    def parse_version(ver):
        return [int(x) if x.isdigit() else x for x in re.split(r'[\.\(\)I]+', ver) if x]

    v = parse_version(version)
    is_vulnerable = False

    # 4. Compare version against vulnerable builds
    if version.startswith("7.0.3") and 'I' in version:
        is_vulnerable = v <= parse_version("7.0.3.I7.10")
    elif version.startswith("9.3"):
        is_vulnerable = v <= parse_version("9.3.8")

    # 5. Assert only if BFD is enabled and version is affected
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20623. "
        f"Nexus 9000 Series switch with NX-OS version {version} has BFD enabled, "
        "which could allow a remote attacker to cause BFD session flaps and a denial of service. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-bfd-dos-wGQXrzxn"
    )
