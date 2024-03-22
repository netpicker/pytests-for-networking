from comfy.compliance import medium


@medium(
    name='rule_13_delete_the_user_name_admin',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show mgmtuser')
)
def rule_13_delete_the_user_name_admin(commands, ref):
    assert 'admin' not in commands.chk_cmd, ref
