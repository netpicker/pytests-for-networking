from comfy import high


@high(
    name='rule_cve202134703',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_lldp='show running-config | include lldp run'
    ),
)
def rule_cve202134703(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-34703 vulnerability in Cisco IOS Software.
    The vulnerability is due to improper initialization of a buffer in the LLDP message parser.
    An unauthenticated, adjacent attacker could exploit this vulnerability by injecting specific
    LLDP frames into the network and then waiting for an administrator to retrieve the LLDP neighbor
    table, causing the device to reload and resulting in a denial of service condition.
    Note: LLDP must be enabled for the device to be vulnerable.
    """
    # Extract the output of the command to check LLDP configuration
    lldp_output = commands.check_lldp

    # Check if LLDP is enabled
    lldp_enabled = 'lldp run' in lldp_output

    # If LLDP is not enabled, device is not vulnerable
    if not lldp_enabled:
        return

    # Assert that the device is not vulnerable
    assert not lldp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-34703. "
        "The device has LLDP enabled, which could allow an adjacent attacker "
        "to cause a denial of service through crafted LLDP frames. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-lldp-dos-sBnuHSjT"
    )
