from comfy.compliance import medium


@medium(
      name='rule_1_2_ensure_disallow_palindromes_is_selected',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_1_2_ensure_disallow_palindromes_is_selected(commands, ref):
    assert '' in commands.chk_cmd, ref
