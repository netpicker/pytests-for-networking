from comfy.compliance import low


@low(
      name='rule_6_11_3_ensure_console_port_is_set_to_disabled',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_11_3_ensure_console_port_is_set_to_disabled(commands, ref):
    assert '' in commands.chk_cmd, ref
