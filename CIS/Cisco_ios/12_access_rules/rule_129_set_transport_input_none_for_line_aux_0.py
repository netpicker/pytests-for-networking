from comfy.compliance import medium


@medium(
    name='rule_129_set_transport_input_none_for_line_aux_0',
    platform=['cisco_ios', 'cisco_xe'],
    commands=dict(chk_cmd='sh line aux 0 | incl input transport')
)
def rule_129_set_transport_input_none_for_line_aux_0(commands, ref):
    assert 'transport input none' in commands.chk_cmd, ref
