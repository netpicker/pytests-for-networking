from comfy.compliance import low


@low(
    name='rule_163_configuring_kerberos',
    platform=['cisco_ios_xe'],  # Targeting Cisco IOS XE as specified
    commands={
        'show_kerberos_cred': 'show kerberos credentials',
        'show_running_config': 'show running-config'
    }
)
def rule_163_configuring_kerberos(configuration, commands, device, devices):
    """
    Verifies the configuration of Kerberos for network authentication.

    Arguments:
        configuration (str): Full configuration of the device.
        commands (dict): Outputs from specified commands.
        device (object): Current device being tested.
        devices (list): Related devices in the test.

    Raises:
        AssertionError: If Kerberos is not configured correctly or credentials are not set properly.
    """

    kerberos_cred_output = commands.show_kerberos_cred
    config_lines = commands.show_running_config.splitlines()

    # Check if Kerberos is enabled
    assert 'kerberos' in config_lines, "Kerberos is not enabled on this device."

    # Validate the Kerberos local realm is correctly defined
    assert any('kerberos local-realm' in line for line in config_lines), \
        "Kerberos local realm is not defined."

    # Validate Kerberos server settings
    assert any('kerberos server' in line for line in config_lines), \
        "Kerberos server settings are not correctly configured."

    # Ensure a Kerberos realm is defined
    assert any('kerberos realm' in line for line in config_lines), \
        "Kerberos realm is not defined."

    # Check Kerberos credentials to ensure they're available
    assert 'Ticket Granting Ticket' in kerberos_cred_output, \
        "No Ticket Granting Ticket found; check Kerberos credentials."

    # Ensure the configuration does not use the default (disabled) setting
    assert 'no kerberos enable' not in config_lines, \
        "Kerberos is disabled by the default configuration."
