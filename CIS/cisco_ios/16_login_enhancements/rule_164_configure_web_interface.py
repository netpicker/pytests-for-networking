from comfy.compliance import low


@low(
    name='rule_164_configure_web_interface',
    platform=['cisco_ios'],  # Assuming Cisco IOS is the target platform
    commands={
        'show_ip_admission': 'show ip admission',
        'show_running_config': 'show running-config'
    }
)
def rule_164_configure_web_interface(configuration, commands, device, devices):
    """
    Verifies web-based authentication configurations on network interfaces.

    Arguments:
        configuration (str): Full configuration of the device.
        commands (dict): Outputs from specified commands.
        device (object): Device being tested.
        devices (list): Related devices in the test.

    Raises:
        AssertionError: If configurations are not set correctly.
    """

    ip_admission_output = commands.show_ip_admission
    config_lines = commands.show_running_config.splitlines()

    # Check SISF-Based Device Tracking is enabled
    assert 'device-tracking' in config_lines, \
        "SISF-Based Device Tracking is not enabled."

    # Check for HTTP server configuration
    assert 'ip http server' in config_lines, "HTTP server is not configured."

    # Validate web-based authentication on supported interfaces only
    unsupported_types = ['trunk', 'Tunnel', 'Port-channel']
    for line in config_lines:
        if 'interface' in line and 'ip admission' in line:
            interface_type = line.split()[1]
            assert not any(x in interface_type for x in unsupported_types), \
                f"Web-based authentication configured on unsupported interface type: {interface_type}"

    # Validate at least one IP address configured for the HTTP server
    assert any('ip address' in line for line in config_lines), \
        "No IP address configured for HTTP server operation."

    # Check NEAT is disabled where web authentication is enabled
    neat_interfaces = {line.split()[1] for line in config_lines if 'neat' in line}
    admission_interfaces = {line.split()[1] for line in config_lines if 'ip admission' in line}
    assert neat_interfaces.isdisjoint(admission_interfaces), \
        "NEAT and Web-based authentication are configured on the same interfaces."

    # Verify correct RADIUS settings
    radius_settings = [
        'hostname RADIUS_HOST',
        'ip address RADIUS_IP auth-port PORT_NUM acct-port PORT_NUM'
    ]
    for setting in radius_settings:
        assert setting in ip_admission_output, \
            f"RADIUS setting missing or incorrect: {setting}"
