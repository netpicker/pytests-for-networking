from comfy.compliance import medium


@medium(
    name='rule_124_create_access_list_for_use_with_line_vty',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh ip access-list <vty_acl_number>')
)
def rule_124_create_access_list_for_use_with_line_v_ty(commands, ref):
    assert 'rule_124_create_access_list_for_use_with_line_vty' in commands.chk_cmd, ref
