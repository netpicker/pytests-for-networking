from comfy.compliance import medium


@medium(
    name='rule_232_set_ip_address_for_ntp_server',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ntp associations')
)
def rule_232_set_ip_address_for_ntp_server(commands, ref):
    assert '*~' in commands.chk_cmd, ref
