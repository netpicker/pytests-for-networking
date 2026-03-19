from comfy import high

@high(
    name='rule_cve202520145',
    platform=['cisco_ios-xr'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config'
    ),
)
def rule_cve202520145(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20145 in Cisco IOS XR Software.
    
    A vulnerability in the access control list (ACL) processing in the egress direction
    could allow an unauthenticated, remote attacker to bypass a configured ACL.
    
    This affects:
    - 8000 Series Modular Platforms (8608, 8804, 8808, 8812, 8818, IOSXRWBD)
    - NCS 5500 Modular Platforms (NCS S5504, S5508, S5516)
    
    When egress IPv4 or IPv6 ACLs are configured and traffic crosses line cards.
    """

    # Extract command outputs
    show_version_output = commands.show_version
    show_running_config_output = commands.show_running_config

    # Define vulnerable models
    vulnerable_models = [
        '8608', '8804', '8808', '8812', '8818', 'IOSXRWBD',
        'NCS-5504', 'NCS-5508', 'NCS-5516',
        'NCS 5504', 'NCS 5508', 'NCS 5516'
    ]

    # Check if device is a vulnerable model
    is_vulnerable_model = any(model in show_version_output for model in vulnerable_models)

    # If not a vulnerable model, device is not affected
    if not is_vulnerable_model:
        return

    # Define vulnerable software versions for 8000 Series (use specific patterns)
    vulnerable_8000_versions = [
        'Version 24.4.', 'Version 24.3.', 'Version 24.2.', 'Version 24.1.',
        'Version 23.', 'Version 22.', 'Version 21.', 'Version 20.', 'Version 19.', 
        'Version 18.', 'Version 17.', 'Version 16.', 'Version 15.'
    ]

    # Define vulnerable software versions for NCS 5500 (use specific patterns to avoid substring matches)
    vulnerable_ncs5500_versions = [
        'Version 7.10.', 'Version 7.9.', 'Version 7.8.', 'Version 7.7.', 'Version 7.6.', 
        'Version 7.5.', 'Version 7.4.', 'Version 7.3.', 'Version 7.2.', 'Version 7.1.', 'Version 7.0.',
        'Version 6.', 'Version 5.', 'Version 4.', 'Version 3.', 'Version 2.', 'Version 1.',
        'Version 7.11.1\n', 'Version 7.11.2\n', 'Version 7.11.3\n', 'Version 7.11.4\n', 
        'Version 7.11.5\n', 'Version 7.11.6\n', 'Version 7.11.7\n', 'Version 7.11.8\n', 'Version 7.11.9\n',
        'Version 7.11.10', 'Version 7.11.11', 'Version 7.11.12', 'Version 7.11.13', 'Version 7.11.14', 
        'Version 7.11.15', 'Version 7.11.16', 'Version 7.11.17', 'Version 7.11.18', 'Version 7.11.19', 'Version 7.11.20',
        'Version 24.2.1\n', 'Version 24.2.11', 'Version 24.2.12'
    ]

    # Check if running vulnerable version
    is_vulnerable_version = False
    
    # Check for 8000 Series versions
    if any(model in show_version_output for model in ['8608', '8804', '8808', '8812', '8818', 'IOSXRWBD']):
        is_vulnerable_version = any(version in show_version_output for version in vulnerable_8000_versions)
    
    # Check for NCS 5500 versions
    if any(model in show_version_output for model in ['NCS-5504', 'NCS-5508', 'NCS-5516', 'NCS 5504', 'NCS 5508', 'NCS 5516']):
        is_vulnerable_version = any(version in show_version_output for version in vulnerable_ncs5500_versions)

    # If not running vulnerable version, device is not affected
    if not is_vulnerable_version:
        return

    # Check if egress ACLs are configured
    has_egress_ipv4_acl = 'ipv4 access-group' in show_running_config_output and 'egress' in show_running_config_output
    has_egress_ipv6_acl = 'ipv6 access-group' in show_running_config_output and 'egress' in show_running_config_output

    # Device is vulnerable if it's a vulnerable model, running vulnerable version, and has egress ACLs configured
    is_vulnerable = is_vulnerable_model and is_vulnerable_version and (has_egress_ipv4_acl or has_egress_ipv6_acl)

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20145. "
        "The device is running a vulnerable version of Cisco IOS XR Software with egress ACLs configured. "
        "This vulnerability allows an unauthenticated, remote attacker to bypass configured egress ACLs "
        "when traffic crosses line cards. "
        "Please upgrade to a fixed release: "
        "8000 Series: 25.1.1 or later, "
        "NCS 5500: 7.11.21, 24.2.2, 24.3 or later. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-modular-ACL-u5MEPXMm"
    )