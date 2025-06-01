from comfy import high


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
    This rule checks for the CVE-2022-20624 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient validation of incoming CFSoIP packets.
    An unauthenticated, remote attacker could exploit this vulnerability by sending crafted
    CFSoIP packets to an affected device, causing it to reload and resulting in a denial of
    service condition.
    """
    # Extract the output of the command to check CFS configuration
    cfs_output = commands.check_cfs

    # Check if CFSoIP is enabled
    cfs_enabled = 'cfs ipv4 distribute' in cfs_output

    # If CFSoIP is not enabled, device is not vulnerable
    if not cfs_enabled:
        return

    # Assert that the device is not vulnerable
    assert not cfs_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20624. "
        "The device has Cisco Fabric Services over IP (CFSoIP) enabled, "
        "which could allow an unauthenticated attacker to cause a denial of service through crafted "
        "CFSoIP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cfsoip-dos-tpykyDr"
    )
