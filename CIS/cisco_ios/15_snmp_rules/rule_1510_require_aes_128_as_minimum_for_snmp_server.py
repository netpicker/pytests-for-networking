from comfy.compliance import low


@low(
    name='rule_1510_require_aes_128_as_minimum_for_snmp_server',
    platform=['cisco_ios_xe'],  # Targeting Cisco IOS XE as specified
    commands={
        'show_snmp_user': 'show snmp user'
    }
)
def rule_1510_require_aes_128_as_minimum_for_snmp_server(configuration, commands, device, devices):
    """
    Verifies that all SNMPv3 users are configured with AES 128-bit encryption as a minimum standard for privacy.

    Arguments:
        configuration (str): Full configuration of the device.
        commands (dict): Dictionary containing the output of commands specified in the `commands` parameter.
        device (object): Object representing the current device being tested.
        devices (list): List of device objects that may be related to the current test.

    Raises:
        AssertionError: If any SNMPv3 user is not configured with AES 128 encryption.
    """

    snmp_users_output = commands.show_snmp_user.splitlines()
    snmp_v3_users_aes128 = [line for line in snmp_users_output if 'AES 128' in line or 'AES128' in line]

    # Verify that there is at least one SNMPv3 user configured with AES 128
    error_msg = "No SNMPv3 user found with AES 128 encryption. " \
                "Configure at least one user with AES 128 as the privacy protocol."
    assert snmp_v3_users_aes128, error_msg

    # Check for each user that AES 128 is used
    for line in snmp_v3_users_aes128:
        user_details = line.split()
        assert 'priv' in user_details and ('AES128' in user_details or 'AES 128' in user_details), \
            f"User {user_details[0]} is not configured with AES 128 encryption correctly."
