from comfy.compliance import medium


@medium(
      name='rule_1_7_ensure_logging_data_is_monitored',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_1_7_ensure_logging_data_is_monitored(commands, ref):
    assert '' in commands.chk_cmd, ref
