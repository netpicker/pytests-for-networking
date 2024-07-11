from comfy.compliance import low


@low(
      name='rule_6_11_4_ensure_console_port_is_set_as_insecure',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_11_4_ensure_console_port_is_set_as_insecure(commands, ref):
    assert '' in commands.chk_cmd, ref
