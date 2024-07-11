from comfy.compliance import medium


@medium(
      name='rule_6_12_5_ensure_local_logging_is_set_for_interactive_commands',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_12_5_ensure_local_logging_is_set_for_interactive_commands(commands, ref):
    assert '' in commands.chk_cmd, ref
