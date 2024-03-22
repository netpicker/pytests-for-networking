from comfy.compliance import medium


@medium(
    name='rule_125_set_access_class_for_line_vty',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh run | sec vty ')
)
def rule_125_set_access_class_for_line_vty(commands, ref):
    assert 'access-class' in commands.chk_cmd, ref
