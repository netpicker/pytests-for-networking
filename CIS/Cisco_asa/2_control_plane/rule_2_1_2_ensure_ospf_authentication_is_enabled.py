from comfy.compliance import low


@low(
      name='rule_2_1_2_ensure_ospf_authentication_is_enabled',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_2_1_2_ensure_ospf_authentication_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
