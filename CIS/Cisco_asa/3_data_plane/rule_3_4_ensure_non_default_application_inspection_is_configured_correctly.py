from comfy.compliance import medium


@medium(
      name='rule_3_4_ensure_non_default_application_inspection_is_configured_correctly',
      platform=['cisco_asa'],
      commands=dict(chk_cmd='')
)
def rule_3_4_ensure_non_default_application_inspection_is_configured_correctly(commands, ref):
    assert '' in commands.chk_cmd, ref
