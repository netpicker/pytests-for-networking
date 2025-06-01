from comfy import high


@high(
    name='rule_cve202220824',
    platform=['cisco_nxos'],
    commands=dict(
        show_version='show version',
        check_cdp='show running-config | include no cdp enable|cdp enable'
    ),
)
def rule_cve202220824(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20824 vulnerability in Cisco NX-OS Software.
    The vulnerability is due to improper input validation of specific values within Cisco Discovery Protocol messages.
    An unauthenticated, adjacent attacker could exploit this vulnerability by sending malicious CDP packets to an
    affected device, allowing them to execute arbitrary code with root privileges or cause a denial of service condition.
    Note: CDP is enabled by default, and the attacker must be in the same broadcast domain (Layer 2 adjacent).
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
        f"Device {device.name} is vulnerable to CVE-2022-20824. "
        "The device has Cisco Discovery Protocol enabled, "
        "which could allow an adjacent attacker to execute arbitrary code with root privileges or cause a denial of service. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-cdp-dos-ce-wWvPucC9"
    )
