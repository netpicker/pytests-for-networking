from comfy.compliance import medium


@medium(
      name='rule_6_6_10_ensure_at_least_4_set_changes_in_local_passwords',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_6_10_ensure_at_least_4_set_changes_in_local_passwords(commands, ref):
    assert '' in commands.chk_cmd, ref
