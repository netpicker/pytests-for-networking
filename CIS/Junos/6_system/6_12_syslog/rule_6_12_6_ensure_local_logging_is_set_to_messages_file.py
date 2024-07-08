from comfy.compliance import medium


@medium(
      name='rule_6_12_6_ensure_local_logging_is_set_to_messages_file',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_12_6_ensure_local_logging_is_set_to_messages_file(commands, ref):
    assert '' in commands.chk_cmd, ref
