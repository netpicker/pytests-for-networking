from comfy.compliance import medium


@medium(
      name='rule_1_10_11_ensure_email_logging_is_configured_for_critical_to_emergency',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_10_11_ensure_email_logging_is_configured_for_critical_to_emergency(commands, ref):
    assert '' in commands.chk_cmd, ref
