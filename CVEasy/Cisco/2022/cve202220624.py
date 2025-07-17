from comfy import high
import re

@high(
    name='rule_cve202220624',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_cfs='show running-config | include cfs ipv4 distribute'
    ),
)
def rule_cve202220624(configuration, commands, device, devices):
    """
    CVE-2022-20624: NX-OS CFSoIP DoS vulnerability.
    Affects NX-OS ≤ 7.0(3)I7(10) or ≤ 9.3(8), only if CFSoIP is enabled.
    """
    cfs_output = commands.check_cfs
    version_output = commands.show_version

    # Check if CFSoIP is enabled
    cfs_enabled = 'cfs ipv4 distribute' in cfs_output
    if not cfs_enabled:
        return  # Not vulnerable if CFSoIP is off

    # Extract NX-OS version from show version
    match = re.search(r'NXOS:\s+version\s+([\w\.\(\)]+)', version_output, re.IGNORECASE)
    if not match:
        return  # Version unknown, skip

    version = match.group(1)

    def parse_version(v):
        return [int(x) if x.isdigit() else x for x in re.split(r'[\.\(\)I]+', v) if x]

    v = parse_version(version)
    is_vulnerable = False

    if version.startswith("7.0.3") and 'I' in version:
        is_vulnerable = v < parse_version("7.0.3.I7.10")
    elif version.startswith("9.3"):
        is_vulnerable = v < parse_version("9.3.8")

    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2022-20624. "
        f"NX-OS version {version} has CFSoIP enabled, which allows unauthenticated DoS attacks. "
        "Upgrade to a fixed version or disable CFSoIP. "
        "See: https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cfsoip-dos-tpykyDr"
    )
