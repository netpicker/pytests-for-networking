from comfy.compliance import medium


@medium(
    name='rule_123_set_no_exec_for_line_aux_0',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='show running-config | sec aux')
)
def rule_123_set_no_exec_for_line_aux_0(commands, ref):
    assert 'no exec' in commands.chk_cmd, ref
