from comfy import high


@high(
    name='rule_cve202220919',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_cip='show running-config | include cip enable'
    ),
)
def rule_cve202220919(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20919 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient input validation during processing of Common Industrial Protocol (CIP) packets.
    An unauthenticated, remote attacker could exploit this vulnerability by sending malformed CIP packets to an affected device,
    causing it to unexpectedly reload and resulting in a denial of service (DoS) condition.
    """
    # Extract the output of the command to check CIP configuration
    cip_output = commands.check_cip

    # Check if CIP is enabled
    cip_enabled = 'cip enable' in cip_output

    # Assert that the device is not vulnerable
    assert not cip_enabled, (
        f"Device {device.name} is vulnerable to CVE-2022-20919. "
        "The device has Common Industrial Protocol (CIP) enabled, "
        "which could allow an unauthenticated attacker to cause a denial of service through malformed CIP packets. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-cip-dos-9rTbKLt9"
    )
