from comfy.compliance import medium


@medium(
      name='rule_2_1_2_ensure_message_of_the_day_motd_is_set',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_1_2_ensure_message_of_the_day_motd_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
