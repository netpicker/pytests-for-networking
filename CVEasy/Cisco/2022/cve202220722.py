from comfy import high


@high(
    name='rule_cve202220722',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_iox='show running-config | include iox'
    ),
)
def rule_cve202220722(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20722 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient protection in the Cisco IOx application hosting environment.
    Multiple vulnerabilities could allow an attacker to inject arbitrary commands into the underlying host
    operating system, execute arbitrary code, install applications without authentication, or conduct
    cross-site scripting (XSS) attacks.
    """
    # Extract the output of the command to check IOS configuration
    iox_output = commands.check_iox

    # Check if IOS is configured
    iox_configured = 'iox' in iox_output

    # Assert that the device is not vulnerable
    assert not iox_configured, (
        f"Device {device.name} is vulnerable to CVE-2022-20722. "
        "The device has IOx application hosting configured, "
        "which could allow an attacker to execute arbitrary commands, install unauthorized applications, "
        "or conduct XSS attacks. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iox-yuXQ6hFj"
    )
