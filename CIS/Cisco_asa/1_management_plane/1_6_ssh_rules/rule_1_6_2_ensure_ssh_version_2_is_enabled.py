from comfy.compliance import medium


@medium(
      name='rule_1_6_2_ensure_ssh_version_2_is_enabled',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_6_2_ensure_ssh_version_2_is_enabled(commands, ref):
    assert '' in commands.chk_cmd, ref
