from comfy.compliance import low


@low(
      name='rule_6_11_2_ensure_auxiliary_port_is_set_as_insecure_if_used',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_11_2_ensure_auxiliary_port_is_set_as_insecure_if_used(commands, ref):
    assert '' in commands.chk_cmd, ref
