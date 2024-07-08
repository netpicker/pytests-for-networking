from comfy.compliance import low


@low(
      name='rule_6_10_5_4_ensure_rest_https_is_set_to_use_mutual_authentication',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_4_ensure_rest_https_is_set_to_use_mutual_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
