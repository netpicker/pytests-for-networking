from comfy.compliance import medium


@medium(
      name='rule_4_5_1_ensure_rip_authentication_is_set_to_md5',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_5_1_ensure_rip_authentication_is_set_to_md5(commands, ref):
    assert '' in commands.chk_cmd, ref
