from comfy.compliance import medium


@medium(
      name='rule_4_2_7_ensure_csnp_authentication_check_is_not_set_to_suppressed',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_4_2_7_ensure_csnp_authentication_check_is_not_set_to_suppressed(commands, ref):
    assert '' in commands.chk_cmd, ref
