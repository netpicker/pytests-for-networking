from comfy.compliance import medium


@medium(
      name='rule_1_3_1_ensure_image_integrity_is_correct',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_1_3_1_ensure_image_integrity_is_correct(commands, ref):
    assert '' in commands.chk_cmd, ref
