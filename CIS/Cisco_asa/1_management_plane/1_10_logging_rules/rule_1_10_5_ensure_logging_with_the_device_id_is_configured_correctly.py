from comfy.compliance import medium


@medium(
      name='rule_1_10_5_ensure_logging_with_the_device_id_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_10_5_ensure_logging_with_the_device_id_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref