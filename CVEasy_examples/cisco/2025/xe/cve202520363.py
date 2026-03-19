from comfy import high

@high(
    name='rule_cve202520363',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_ssl_policy='show running-config | section crypto ssl policy',
        show_webvpn='show running-config | section webvpn'
    ),
)
def rule_cve202520363(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20363 vulnerability in Cisco IOS XE Software.
    
    A vulnerability in the web services could allow an authenticated, remote attacker with low 
    user privileges to execute arbitrary code on an affected device. This vulnerability is due 
    to improper validation of user-supplied input in HTTP requests.
    
    The device is vulnerable if:
    - Running a vulnerable IOS XE version
    - AND Remote Access SSL VPN feature is enabled
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions based on the advisory
    # These are versions that need to be checked against the Software Checker
    # For this rule, we'll check for common vulnerable version patterns
    vulnerable_version_patterns = [
        '16.3.', '16.4.', '16.5.', '16.6.', '16.7.', '16.8.', '16.9.',
        '16.10.', '16.11.', '16.12.',
        '17.1.', '17.2.', '17.3.', '17.4.', '17.5.', '17.6.', '17.7.',
        '17.8.', '17.9.', '17.10.', '17.11.', '17.12.'
    ]

    # Check if the current device's software version matches vulnerable patterns
    version_vulnerable = any(pattern in version_output for pattern in vulnerable_version_patterns)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check if Remote Access SSL VPN is enabled
    ssl_policy_output = commands.show_ssl_policy
    
    # SSL VPN is vulnerable if there's a crypto ssl policy without 'shutdown'
    ssl_vpn_enabled = False
    if ssl_policy_output and 'crypto ssl policy' in ssl_policy_output:
        # Check if any policy exists without shutdown command
        # If we see a policy definition and no 'shutdown' in the same block, it's enabled
        if 'shutdown' not in ssl_policy_output or ssl_policy_output.strip().endswith('port 443'):
            ssl_vpn_enabled = True

    # If SSL VPN is enabled, the device is vulnerable
    assert not ssl_vpn_enabled, (
        f"Device {device.name} is vulnerable to CVE-2025-20363. "
        "The device is running a vulnerable IOS XE version AND has Remote Access SSL VPN enabled. "
        "An authenticated, remote attacker with low user privileges could execute arbitrary code as root. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-http-code-exec-WmfP3h3O"
    )