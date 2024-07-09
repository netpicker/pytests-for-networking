from comfy.compliance import low


@low(
      name='rule_1_4_2_1_ensure_tacacs__radius_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_4_2_1_ensure_tacacs__radius_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref
