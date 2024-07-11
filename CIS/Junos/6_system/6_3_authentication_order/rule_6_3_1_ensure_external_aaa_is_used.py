from comfy.compliance import medium


@medium(
      name='rule_6_3_1_ensure_external_aaa_is_used',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_3_1_ensure_external_aaa_is_used(commands, ref):
    assert '' in commands.chk_cmd, ref
