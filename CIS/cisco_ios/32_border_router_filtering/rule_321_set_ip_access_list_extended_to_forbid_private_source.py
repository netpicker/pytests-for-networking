from comfy.compliance import low


@low(
    name='rule_321_set_ip_access_list_extended_to_forbid_private_source_addresses_from_external_networks',
    platform=['cisco_ios_xe'],  # Targeting Cisco IOS XE as specified
    commands={
        'show_ip_access_list': 'show ip access-list TEST'
    }
)
def rule_321_set_ip_access_list_extended_to_forbid_private_source_addresses_from_external_networks(commands, ref):
    """
    Verifies that 'ip access-list extended' is correctly configured to deny private source IP addresses
    from external networks.

    Arguments:
        configuration (str): Full configuration of the device.
        commands (dict): Dictionary containing the output of commands specified in the `commands` parameter.
        device (object): Object representing the current device being tested.
        devices (list): List of device objects that may be related to the current test.

    Raises:
        AssertionError: If the access list does not properly deny traffic from private IP addresses or
        other specified ranges.
    """

    access_list_output = commands.show_ip_access_list.splitlines()
    required_deny_entries = [
        'deny ip 127.0.0.0 0.255.255.255 any log',
        'deny ip 10.0.0.0 0.255.255.255 any log',
        'deny ip 172.16.0.0 0.15.255.255 any log',
        'deny ip 192.168.0.0 0.0.255.255 any log',
        'deny ip 192.0.2.0 0.0.0.255 any log',
        'deny ip 169.254.0.0 0.0.255.255 any log',
        'deny ip 224.0.0.0 31.255.255.255 any log',
        'deny ip host 255.255.255.255 any log',
        'deny any any log'
    ]

    # Check each required entry is present in the access-list configuration
    for entry in required_deny_entries:
        assert any(entry in line for line in access_list_output), f"Missing or incorrect access list entry: {entry}"

    # Ensure there is a corresponding 'permit' entry that correctly specifies allowed traffic
    permit_entries = [line for line in access_list_output if 'permit' in line]
    assert permit_entries, ref
