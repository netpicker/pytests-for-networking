from comfy.compliance import medium


@medium(
      name='rule_6_10_2_2_ensure_web_management_is_set_to_use_https',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_2_ensure_web_management_is_set_to_use_https(commands, ref):
    assert '' in commands.chk_cmd, ref
