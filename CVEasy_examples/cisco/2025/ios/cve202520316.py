from comfy import high


@high(
    name='rule_cve202520316',
    platform=['cisco_ios'],
    commands=dict(
        show_version='show version',
        show_running_config='show running-config | include interface Vlan|out$'
    ),
)
def rule_cve202520316(configuration, commands, device, devices):
    """
    This rule checks for the presence of CVE-2025-20316 vulnerability in Cisco Catalyst 9500X and 9600X Series Switches.
    The vulnerability is due to the flooding of traffic from an unlearned MAC address on a switch virtual interface (SVI)
    that has an egress ACL applied. An attacker could exploit this vulnerability by causing the VLAN to flush its MAC
    address table, allowing them to bypass an egress ACL on an affected device.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if the device is a Catalyst 9500X or 9600X Series Switch
    is_catalyst_9500x = 'Catalyst 9500X' in version_output or 'C9500X' in version_output
    is_catalyst_9600x = 'Catalyst 9600X' in version_output or 'C9600X' in version_output
    
    # Only Catalyst 9500X and 9600X Series are vulnerable
    is_vulnerable_platform = is_catalyst_9500x or is_catalyst_9600x

    # If not a vulnerable platform, no need to check further
    if not is_vulnerable_platform:
        return

    # Check if running Cisco IOS XE Software
    is_ios_xe = 'IOS XE' in version_output

    # If not running IOS XE, not vulnerable
    if not is_ios_xe:
        return

    # Check for egress ACL configuration on SVI
    config_output = commands.show_running_config

    # Check if there's an egress ACL configured on an SVI (interface Vlan with "out" at end of line)
    has_egress_acl_on_svi = 'interface Vlan' in config_output and ' out' in config_output

    # Device is vulnerable if it's a 9500X/9600X running IOS XE with egress ACL on SVI
    is_vulnerable = has_egress_acl_on_svi

    # Assert that the device is not vulnerable
    # If the device is vulnerable, the test will fail, indicating the presence of the vulnerability
    assert not is_vulnerable, (
        f"Device {device.name} is vulnerable to CVE-2025-20316. "
        "The device is a Cisco Catalyst 9500X or 9600X Series Switch running IOS XE Software "
        "with an egress ACL configured on a switch virtual interface (SVI), "
        "which makes it susceptible to ACL bypass attacks through MAC address table flooding. "
        "For more information, see https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cat9k-acl-L4K7VXgD"
    )