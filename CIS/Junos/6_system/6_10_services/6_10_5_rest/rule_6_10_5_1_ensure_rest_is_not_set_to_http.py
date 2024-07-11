from comfy.compliance import medium


@medium(
      name='rule_6_10_5_1_ensure_rest_is_not_set_to_http',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_1_ensure_rest_is_not_set_to_http(commands, ref):
    assert '' in commands.chk_cmd, ref
