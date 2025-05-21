from comfy import high


@high(
    name='rule_cve20211385',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox'
    ),
)
def rule_cve20211385(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2021-1385 vulnerability in Cisco IOx application hosting environment.
    The vulnerability is due to insufficient validation of URIs in IOx API requests. An authenticated,
    remote attacker could exploit this vulnerability by sending a crafted API request containing
    directory traversal character sequences to an affected device, allowing them to read and write
    arbitrary files on the underlying operating system.
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
        f"Device {device.name} is vulnerable to CVE-2021-1385. "
        "The device has IOx enabled, which could allow an authenticated attacker "
        "to conduct directory traversal attacks and read/write arbitrary files on the underlying OS. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-pt-hWGcPf7g"
    )
