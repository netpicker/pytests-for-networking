from comfy.compliance import medium


@medium(
      name='rule_6_8_4_ensure_ms_chapv2_radius_authentication',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_8_4_ensure_ms_chapv2_radius_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
