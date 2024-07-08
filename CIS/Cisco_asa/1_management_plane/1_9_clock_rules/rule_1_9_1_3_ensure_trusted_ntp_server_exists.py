from comfy.compliance import medium


@medium(
      name='rule_1_9_1_3_ensure_trusted_ntp_server_exists',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_9_1_3_ensure_trusted_ntp_server_exists(commands, ref):
    assert '' in commands.chk_cmd, ref
