from comfy.compliance import medium


@medium(
      name='rule_1_4_ensure_configuration_is_backed_up_on_a_regular_schedule',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_1_4_ensure_configuration_is_backed_up_on_a_regular_schedule(commands, ref):
    assert '' in commands.chk_cmd, ref
