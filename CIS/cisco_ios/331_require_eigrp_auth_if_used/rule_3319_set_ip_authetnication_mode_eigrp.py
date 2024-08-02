from comfy import medium


@medium(
    name='rule_3319_set_ip_authentication_mode_eigrp',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'interface_eigrp_auth_mode_config': 'sh run int {interface_name} | incl authentication mode'}
)
def rule_3319_set_ip_authentication_mode_eigrp(commands, ref):
    # Extracting the EIGRP MD5 authentication mode configuration from the command output
    interface_eigrp_auth_mode_config = commands.interface_eigrp_auth_mode_config

    # Verifying that the EIGRP authentication mode is set to MD5 on the interface
    assert 'ip authentication mode eigrp md5' in interface_eigrp_auth_mode_config, ref
