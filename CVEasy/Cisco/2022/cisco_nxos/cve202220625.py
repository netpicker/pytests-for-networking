from comfy import high


@high(
    name='rule_cve202220625',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_cdp='show running-config | include no cdp enable|cdp enable'
    ),
)
def rule_cve202220625(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20625 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper handling of Cisco Discovery Protocol messages.
    An unauthenticated, adjacent attacker could exploit this vulnerability by sending
    malicious CDP packets to an affected device, causing the CDP service to fail and
    restart, and in rare conditions, causing the entire device to restart.
    """
    # Extract the output of the command to check CDP configuration
    cdp_output = commands.check_cdp

    # Check if CDP is enabled
    cdp_enabled = 'cdp enable' in cdp_output

    # If CDP is not enabled, device is not vulnerable
    if not cdp_enabled:
        return

    # Assert that the device is not vulnerable
    assert not cdp_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20625. "
        "The device has Cisco Discovery Protocol enabled, "
        "which could allow an adjacent attacker to cause a denial of service through "
        "malicious CDP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cdp-dos-G8DPLWYG"
    )
