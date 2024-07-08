from comfy.compliance import medium


@medium(
      name='rule_6_10_8_ensure_ftp_service_is_not_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_8_ensure_ftp_service_is_not_set(commands, ref):
    assert '' in commands.chk_cmd, ref
