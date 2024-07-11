from comfy.compliance import medium


@medium(
      name='rule_6_10_3_1_ensure_xnm_clear_text_service_is_not_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_3_1_ensure_xnm_clear_text_service_is_not_set(commands, ref):
    assert '' in commands.chk_cmd, ref
