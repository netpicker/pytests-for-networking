from comfy.compliance import medium


@medium(
    name='rule_114_set_login_authentication_for_line_vty',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_con='show running-config | sec line con', chk_vty='show running-config | sec line vty')
)
def rule_114_set_login_authentication_for_line_vty(commands, ref):
    assert 'login authentication' in commands.chk_con, ref
    assert 'login authentication' in commands.chk_vty, ref
