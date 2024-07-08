from comfy.compliance import medium


@medium(
      name='rule_6_7_4_ensure_ntp_uses_version_4',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_7_4_ensure_ntp_uses_version_4(commands, ref):
    assert '' in commands.chk_cmd, ref
