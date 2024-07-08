from comfy.compliance import medium


@medium(
      name='rule_6_4_2_ensure_diagnostic_port_authentication_uses_a_complex_password',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_4_2_ensure_diagnostic_port_authentication_uses_a_complex_password(commands, ref):
    assert '' in commands.chk_cmd, ref
