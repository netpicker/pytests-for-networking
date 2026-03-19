from comfy import high

@high(
    name='rule_cve202552985',
    platform=['juniper_junos'],
    commands=dict(
        show_version='show version',
        show_firewall_config='show configuration firewall | display set',
        show_interfaces_config='show configuration interfaces | display set'
    ),
)
def rule_cve202552985(configuration, commands, device, devices):
    """
    This rule checks for CVE-2025-52985 vulnerability in Juniper Networks Junos OS Evolved.
    The vulnerability allows an unauthenticated, network-based attacker to bypass security
    restrictions when a firewall filter applied to lo0 or re:mgmt interface references a
    prefix list with more than 10 entries.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Define the vulnerable versions for Junos OS Evolved
    vulnerable_versions = [
        '23.2R2-S3-EVO',
        '23.4R2-S3-EVO', '23.4R2-S4-EVO',
        '24.2R2-EVO',
        '24.4R1-EVO', '24.4R1-S1-EVO', '24.4R1-S2-EVO'
    ]

    # Check if the current version is vulnerable (must be Junos OS Evolved)
    is_evolved = 'EVO' in version_output or 'Evolved' in version_output
    
    if not is_evolved:
        return

    version_vulnerable = any(version in version_output for version in vulnerable_versions)

    # If version is not vulnerable, exit early
    if not version_vulnerable:
        return

    # Check for vulnerable configuration
    firewall_config = commands.show_firewall_config
    interfaces_config = commands.show_interfaces_config

    # Check if firewall filters are applied to lo0 or re:mgmt interfaces
    has_lo0_filter = 'set interfaces lo0' in interfaces_config and 'filter' in interfaces_config
    has_remgmt_filter = 'set interfaces re:mgmt' in interfaces_config or 'set interfaces re0' in interfaces_config

    if not (has_lo0_filter or has_remgmt_filter):
        return

    # Check if firewall filter references prefix-list with from prefix-list
    has_prefix_list_reference = 'from prefix-list' in firewall_config

    if not has_prefix_list_reference:
        return

    # Check if any prefix list has more than 10 entries
    prefix_list_entries = {}
    for line in firewall_config.splitlines():
        if 'set firewall prefix-list' in line:
            parts = line.split()
            if len(parts) >= 4:
                list_name = parts[3]
                if list_name not in prefix_list_entries:
                    prefix_list_entries[list_name] = 0
                prefix_list_entries[list_name] += 1

    has_large_prefix_list = any(count > 10 for count in prefix_list_entries.values())

    # Assert that the device is not vulnerable
    assert not has_large_prefix_list, (
        f"Device {device.name} is vulnerable to CVE-2025-52985. "
        "The device is running a vulnerable version of Junos OS Evolved with a firewall filter "
        "applied to lo0 or re:mgmt interface that references a prefix list with more than 10 entries. "
        "This allows an unauthenticated, network-based attacker to bypass security restrictions. "
        "For more information, see https://supportportal.juniper.net/JSA88125"
    )