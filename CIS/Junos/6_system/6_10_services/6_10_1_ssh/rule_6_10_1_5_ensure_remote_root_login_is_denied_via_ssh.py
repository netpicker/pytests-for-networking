from comfy.compliance import medium


@medium(
      name='rule_6_10_1_5_ensure_remote_root_login_is_denied_via_ssh',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_5_ensure_remote_root_login_is_denied_via_ssh(commands, ref):
    assert '' in commands.chk_cmd, ref
