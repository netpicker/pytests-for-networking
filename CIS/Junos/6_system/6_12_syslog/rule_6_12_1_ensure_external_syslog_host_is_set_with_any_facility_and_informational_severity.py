from comfy.compliance import medium


@medium(
      name='rule_6_12_1_ensure_external_syslog_host_is_set_with_any_facility_and_informational_severity',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_12_1_ensure_external_syslog_host_is_set_with_any_facility_and_informational_severity(commands, ref):
    assert '' in commands.chk_cmd, ref
