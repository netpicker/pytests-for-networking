from comfy.compliance import low


@low(
      name='rule_6_12_2_ensure_at_least_2_external_syslog_hosts_are_set_with_any_info',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_12_2_ensure_at_least_2_external_syslog_hosts_are_set_with_any_info(commands, ref):
    assert '' in commands.chk_cmd, ref
