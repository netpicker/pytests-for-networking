from comfy import high


@high(
    name='rule_cve202320076',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox'
    ),
)
def rule_cve202320076(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2023-20076 vulnerability in Cisco IOS Software.
    The vulnerability is due to incomplete sanitization of parameters that are passed in for
    activation of an application in the Cisco IOx application hosting environment. An attacker
    could exploit this vulnerability by deploying and activating an application with a crafted
    activation payload file.
    """
    # Extract the output of the command to check IOx configuration
    iox_output = commands.check_iox

    # Check if IOx is configured
    iox_configured = 'iox' in iox_output

    # Assert that the device is not vulnerable
    assert not iox_configured, (
        f"Device {device.name} is vulnerable to CVE-2023-20076. "
        "The device has IOx application hosting configured, "
        "which could allow an authenticated attacker to execute arbitrary commands as root. "
        "For more information, see"
        "https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-8whGn5dL"
    )
