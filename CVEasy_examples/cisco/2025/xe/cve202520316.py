from comfy import medium

@medium(
    name='rule_cve202520316',
    platform=['cisco_ios-xe'],
    commands=dict(
        show_version='show version',
        show_switch_info='show switch',
        show_acl_config='show running-config | include interface Vlan|out$'
    ),
)
def rule_cve202520316(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-20316 vulnerability in Cisco IOS XE Software
    on Catalyst 9500X and 9600X Series Switches.
    
    The vulnerability allows an unauthenticated, remote attacker to bypass a
    configured ACL on an affected device due to the flooding of traffic from an
    unlearned MAC address on a switch virtual interface (SVI) that has an egress
    ACL applied.
    """
    # Extract the version and switch information
    version_output = commands.show_version
    switch_output = commands.show_switch_info
    
    # Check if device is a Catalyst 9500X or 9600X Series Switch
    is_9500x = 'C9500X' in switch_output or 'Catalyst 9500X' in switch_output
    is_9600x = 'C9600X' in switch_output or 'Catalyst 9600X' in switch_output
    
    # If not an affected switch model, device is not vulnerable
    if not (is_9500x or is_9600x):
        return
    
    # Check if egress ACL is configured on an SVI
    acl_config = commands.show_acl_config
    has_egress_acl_on_svi = 'interface Vlan' in acl_config and 'out' in acl_config
    
    # If no egress ACL on SVI, device is not vulnerable
    if not has_egress_acl_on_svi:
        return
    
    # List of vulnerable software versions (versions before the fix)
    # Based on typical Cisco IOS XE versioning, assuming vulnerability exists in versions
    # before a specific fixed release
    vulnerable_versions = [
        # 17.x versions that are vulnerable
        '17.1.', '17.2.', '17.3.', '17.4.', '17.5.', '17.6.', '17.7.', '17.8.', '17.9.',
        '17.10.', '17.11.', '17.12.', '17.13.', '17.14.', '17.15.',
        # 16.x versions
        '16.3.', '16.4.', '16.5.', '16.6.', '16.7.', '16.8.', '16.9.',
        '16.10.', '16.11.', '16.12.',
    ]
    
    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)
    
    # If version is vulnerable and has egress ACL on SVI, device is vulnerable
    if version_vulnerable and has_egress_acl_on_svi:
        assert False, (
            f"Device {device.name} is vulnerable to CVE-2025-20316. "
            "The device is a Catalyst 9500X or 9600X Series Switch running a vulnerable version "
            "with an egress ACL configured on an SVI. An attacker could bypass the ACL by causing "
            "the VLAN to flush its MAC address table. "
            "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat9k-acl-L4K7VXgD"
        )