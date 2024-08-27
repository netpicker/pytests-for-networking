from comfy import medium


@medium(
    name='rule_3335_set_ip_rip_authentication_mode_to_md5',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'interface_rip_mode_config': 'sh run int {interface_name}'}
)
def rule_3335_set_ip_rip_authentication_mode_to_md5(commands, ref):
    # Replace {interface_name} with the actual interface you want to test.

    # Extracting the RIP v2 MD5 authentication mode configuration from the command output
    interface_rip_mode_config = commands.interface_rip_mode_config

    # Verifying that the RIP v2 authentication mode is set to MD5 on the interface
    assert 'ip rip authentication mode md5' in interface_rip_mode_config, ref
