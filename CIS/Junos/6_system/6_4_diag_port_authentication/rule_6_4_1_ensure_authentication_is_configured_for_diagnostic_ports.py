from comfy.compliance import medium


@medium(
      name='rule_6_4_1_ensure_authentication_is_configured_for_diagnostic_ports',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_4_1_ensure_authentication_is_configured_for_diagnostic_ports(commands, ref):
    assert '' in commands.chk_cmd, ref
