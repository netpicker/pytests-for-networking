from comfy.compliance import medium


@medium(
      name='rule_6_10_2_4_ensure_idle_timeout_is_set_for_web_management',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_4_ensure_idle_timeout_is_set_for_web_management(commands, ref):
    assert '' in commands.chk_cmd, ref
