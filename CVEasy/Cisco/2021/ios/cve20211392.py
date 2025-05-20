from comfy import high


@high(
    name='rule_cve20211392',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_cip='show running-config | include cip security'
    ),
)
def rule_cve20211392(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1392 vulnerability in Cisco IOS Software.
    The vulnerability is due to incorrect permissions associated with the 'show cip security' CLI command.
    An authenticated, local attacker could exploit this vulnerability by issuing the command to retrieve
    the password for CIP on an affected device, allowing them to reconfigure the device as an administrative user.
    Note: The Common Industrial Protocol (CIP) feature must be configured for the device to be vulnerable.
    """
    # Extract the output of the command to check CIP configuration
    cip_output = commands.check_cip

    # Check if CIP security is configured
    cip_enabled = 'cip security' in cip_output

    # If CIP is not enabled, device is not vulnerable
    if not cip_enabled:
        return

    # Assert that the device is not vulnerable
    assert not cip_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1392. "
        "The device has CIP security configured, which could allow an authenticated attacker "
        "to retrieve the CIP password and reconfigure the device with administrative privileges. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-XE-SAP-OPLbze68"
    )
