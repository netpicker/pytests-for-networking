from comfy.compliance import medium


@medium(
      name='rule_6_10_1_2_ensure_ssh_is_restricted_to_version_2',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_1_2_ensure_ssh_is_restricted_to_version_2(commands, ref):
    assert '' in commands.chk_cmd, ref
