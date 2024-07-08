from comfy.compliance import medium


@medium(
      name='rule_6_10_2_5_ensure_session_limited_is_set_for_web_management',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_5_ensure_session_limited_is_set_for_web_management(commands, ref):
    assert '' in commands.chk_cmd, ref
