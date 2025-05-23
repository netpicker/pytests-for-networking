from comfy import high


@high(
    name='rule_cve20211367',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_pim='show running-config | include feature pim|ip pim'
    ),
)
def rule_cve20211367(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1367 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to insufficient input validation in the Protocol Independent Multicast (PIM) feature.
    An unauthenticated, adjacent attacker could exploit this vulnerability by sending crafted PIM packets
    to an affected device, causing a traffic loop that results in a denial of service condition.
    Note: The PIM feature must be enabled for the device to be vulnerable.
    """
    # Extract the output of the command to check PIM configuration
    pim_output = commands.check_pim

    # Check if PIM is enabled
    pim_enabled = any(feature in pim_output for feature in [
        'feature pim',
        'ip pim'
    ])

    # If PIM is not enabled, device is not vulnerable
    if not pim_enabled:
        return

    # Assert that the device is not vulnerable
    assert not pim_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1367. "
        "The device has PIM enabled, which could allow an adjacent attacker "
        "to cause a traffic loop and denial of service through crafted PIM packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-pim-dos-Y8SjMz4"
    )
