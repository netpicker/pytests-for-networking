from comfy import high


@high(
    name='rule_cve20211460',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox'
    ),
)
def rule_cve20211460(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1460 vulnerability in Cisco IOx Application Framework.
    The vulnerability is due to insufficient error handling during packet processing. An unauthenticated,
    remote attacker could exploit this vulnerability by sending a high and sustained rate of crafted TCP
    traffic to the IOx web server on an affected device, causing a denial of service (DoS) condition.
    Note: The IOx feature must be enabled for the device to be vulnerable.
    """
    # Extract the output of the command to check IOx configuration
    iox_output = commands.check_iox

    # Check if IOx is enabled
    iox_enabled = 'iox' in iox_output

    # If IOx is not enabled, device is not vulnerable
    if not iox_enabled:
        return

    # Assert that the device is not vulnerable
    assert not iox_enabled, (
        f"Device {device.name} is vulnerable to CVE-2021-1460. "
        "The device has IOx enabled, which could allow an unauthenticated attacker "
        "to cause a denial of service through crafted TCP traffic to the IOx web server. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-dos-4Fgcjh6"
    )
