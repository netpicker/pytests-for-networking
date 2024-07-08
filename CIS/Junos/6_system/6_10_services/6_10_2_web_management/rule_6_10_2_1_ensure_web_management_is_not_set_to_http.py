from comfy.compliance import medium


@medium(
      name='rule_6_10_2_1_ensure_web_management_is_not_set_to_http',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_1_ensure_web_management_is_not_set_to_http(commands, ref):
    assert '' in commands.chk_cmd, ref
