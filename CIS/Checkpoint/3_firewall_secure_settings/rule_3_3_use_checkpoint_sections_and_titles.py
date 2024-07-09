from comfy.compliance import medium


@medium(
      name='rule_3_3_use_checkpoint_sections_and_titles',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_3_3_use_checkpoint_sections_and_titles(commands, ref):
    assert '' in commands.chk_cmd, ref
