from comfy.compliance import medium


@medium(
      name='rule_3_1_2_ensure_access_profile_is_set_to_use_chap',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_1_2_ensure_access_profile_is_set_to_use_chap(commands, ref):
    assert '' in commands.chk_cmd, ref
