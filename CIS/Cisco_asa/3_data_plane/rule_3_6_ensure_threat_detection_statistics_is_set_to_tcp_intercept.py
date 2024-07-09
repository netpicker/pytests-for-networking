from comfy.compliance import medium


@medium(
      name='rule_3_6_ensure_threat_detection_statistics_is_set_to_tcp_intercept',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_6_ensure_threat_detection_statistics_is_set_to_tcp_intercept(commands, ref):
    assert '' in commands.chk_cmd, ref
