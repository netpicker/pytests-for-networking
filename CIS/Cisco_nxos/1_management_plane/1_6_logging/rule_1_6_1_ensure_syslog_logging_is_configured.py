from comfy.compliance import low


@low(
      name='rule_1_6_1_ensure_syslog_logging_is_configured',
      platform=['cisco_nxos'],
      commands=dict(chk_cmd='')
)
def rule_1_6_1_ensure_syslog_logging_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
