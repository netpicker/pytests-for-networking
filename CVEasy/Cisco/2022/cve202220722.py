from comfy import high


@high(
    name='rule_cve202220722',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        check_ios='show running-config | include ios'
    ),
)
def rule_cve202220722(configuration, commands, device, devices):
    """
    This rule checks for the CVE-2022-20722 vulnerability in Cisco IOS Software.
    The vulnerability is due to insufficient protection in the Cisco IOS application hosting environment.
    Multiple vulnerabilities could allow an attacker to inject arbitrary commands into the underlying host
    operating system, execute arbitrary code, install applications without authentication, or conduct
    cross-site scripting (XSS) attacks.
    """
    # Extract the output of the command to check IOS configuration
    ios_output = commands.check_ios

    # Check if IOS is configured
    ios_configured = 'ios' in ios_output

    # Assert that the device is not vulnerable
    assert not ios_configured, (
        f"Device {device.name} is vulnerable to CVE-2022-20722. "
        "The device has IOS application hosting configured, "
        "which could allow an attacker to execute arbitrary commands, install unauthorized applications, "
        "or conduct XSS attacks. "
        "For more information, see "
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-yuXQ6hFj"
    )
