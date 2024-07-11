from comfy.compliance import low


@low(
      name='rule_6_20_ensure_default_address_selection_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_20_ensure_default_address_selection_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
