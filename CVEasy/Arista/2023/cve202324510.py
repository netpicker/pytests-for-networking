from comfy import high


@high(
    name='rule_cve202324510',
    platform=['arista_eos'],
    commands=dict(
        show_version='show version',
        show_ip_helper='show running-config | include ip helper-address'
    ),
)
def rule_cve202324510(configuration, commands, device, devices):
    """
    This rule checks for CVE-2023-24510 vulnerability in Arista EOS devices.
    The vulnerability allows a malformed DHCP packet to cause the DHCP relay agent to restart
    when specific ip helper-address configurations are present on the same interface.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # List of vulnerable software versions
    vulnerable_versions = [
        # 4.25.x versions
        '4.25.0F', '4.25.10M',
        # 4.26.x versions
        '4.26.0F', '4.26.9M',
        # 4.27.x versions
        '4.27.0F', '4.27.9M',
        # 4.28.x versions
        '4.28.0F', '4.28.6.1M',
        # 4.29.x versions
        '4.29.0F', '4.29.1F'
    ]

    # Check if the current device's software version is in the list of vulnerable versions
    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, no need to check further
    if not version_vulnerable:
        return

    # Check for vulnerable ip helper-address configurations
    helper_config = commands.show_ip_helper
    config_lines = helper_config.splitlines()

    # Track interfaces with multiple helper addresses
    interface_helpers = {}
    current_interface = None

    # Parse configuration to find interfaces with multiple helper addresses
    for line in config_lines:
        if 'interface' in line:
            current_interface = line
            interface_helpers[current_interface] = {
                'source_interface': False,
                'vrf': False,
                'basic': False
            }
        elif current_interface and 'ip helper-address' in line:
            if 'source-interface' in line:
                interface_helpers[current_interface]['source_interface'] = True
            elif 'vrf' in line:
                interface_helpers[current_interface]['vrf'] = True
            else:
                interface_helpers[current_interface]['basic'] = True

    # Check for vulnerable configurations
    vulnerable_config = False
    for interface, config in interface_helpers.items():
        # Scenario One: One command uses source-interface, second command is basic
        if config['source_interface'] and config['basic']:
            vulnerable_config = True
            break
        # Scenario Two: One command in VRF, second command is basic
        if config['vrf'] and config['basic']:
            vulnerable_config = True
            break

    # Assert that the device is not vulnerable
    assert not vulnerable_config, (
        f"Device {device.name} is vulnerable to CVE-2023-24510. "
        "The device is running a vulnerable version AND has multiple ip helper-address commands "
        "configured on the same interface in a vulnerable combination:\n"
        "- One command using source-interface with a basic command, or\n"
        "- One command in a VRF with a basic command\n"
        "Recommended fixes:\n"
        "- Upgrade to one of the following fixed versions:\n"
        "  * 4.29.2F or later for 4.29.x train\n"
        "  * 4.28.7M or later for 4.28.x train\n"
        "  * 4.27.10M or later for 4.27.x train\n"
        "  * 4.26.10M or later for 4.26.x train\n"
        "- Or apply the hotfix for supported versions\n"
        "For more information, see"
        "https://www.arista.com/en/support/advisories-notices/security-advisory/17445-security-advisory-0087"
    )
