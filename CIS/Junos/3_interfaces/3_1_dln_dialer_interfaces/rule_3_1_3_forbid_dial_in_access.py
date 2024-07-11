from comfy.compliance import low


@low(
      name='rule_3_1_3_forbid_dial_in_access',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_3_1_3_forbid_dial_in_access(commands, ref):
    assert '' in commands.chk_cmd, ref
