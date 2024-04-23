from comfy.compliance import medium


@medium(
    name='rule_314_set_ip_verify_unicast_source_reachable_via',
    platform=['cisco_ios'],  # Assuming Cisco IOS is the target platform
    commands={
        'show_urpf': 'sh ip int {interface} | include verify source'
    }
)
def rule_314_set_ip_verify_unicast_source_reachable_via(configuration, commands, device, devices):
    """
    Verifies that Unicast Reverse Path Forwarding (uRPF) is enabled on specified interfaces.

    Arguments:
        configuration (str): Full configuration of the device.
        commands (dict): Dictionary containing the output of commands specified in the `commands` parameter.
        device (object): Object representing the current device being tested.
        devices (list): List of device objects that may be related to the current test.

    Raises:
        AssertionError: If uRPF is not correctly configured on the required interfaces.
    """

    required_interfaces = ['GigabitEthernet0/1', 'GigabitEthernet0/2']  # Example interfaces
    missing_urpf = []

    for interface in required_interfaces:
        # Dynamically modify the command to check each interface
        device_specific_command = f'sh ip int {interface} | include verify source'
        urpf_status = device.cli(device_specific_command)

        # Validate uRPF is active; 'urpf_status' should not be empty if uRPF is configured
        if not urpf_status.strip():
            missing_urpf.append(interface)

    # Assert no interfaces are missing uRPF configuration
    assert not missing_urpf, f"uRPF is not configured on the following interfaces: {', '.join(missing_urpf)}"
