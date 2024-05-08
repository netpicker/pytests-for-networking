@medium(
    name='rule_1_1_ensure_device_is_running_current_junos_software',
    platform=['juniper_junos'],
    commands={'show_version': 'show version'}
)
def rule_1_1_ensure_device_is_running_current_junos_software(commands, ref):
    # Extract the software version from the command output
    show_version_output = commands['show_version']

    # Define the current expected version of Junos software
    current_junos_version = "20.4R2.14"  # Update this version as necessary to reflect the current standard

    # Check if the current software version is as expected
    assert current_junos_version in show_version_output, ref
