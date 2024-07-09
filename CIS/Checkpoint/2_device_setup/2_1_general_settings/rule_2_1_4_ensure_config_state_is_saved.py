from comfy.compliance import medium


@medium(
      name='rule_2_1_4_ensure_config_state_is_saved',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_4_ensure_config_state_is_saved(commands, ref):
    assert '' in commands.chk_cmd, ref
