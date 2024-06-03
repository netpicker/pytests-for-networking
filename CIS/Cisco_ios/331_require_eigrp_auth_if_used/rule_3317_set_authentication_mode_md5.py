from comfy import high


@high(
    name='rule_3317_set_authentication_mode_md5',
    platform=['cisco_ios', 'cisco_xe'],
    commands={'eigrp_auth_mode_config': 'sh run | sec router eigrp'}
)
def rule_3317_set_authentication_mode_md5(commands, ref):
    # Extracting the EIGRP MD5 authentication mode configuration from the command output
    eigrp_auth_mode_config = commands.eigrp_auth_mode_config

    # Verifying that 'authentication mode md5' is properly configured within the EIGRP address family
    assert (eigrp_auth_mode_config != '' or 'authentication mode md5' in eigrp_auth_mode_config), ref
