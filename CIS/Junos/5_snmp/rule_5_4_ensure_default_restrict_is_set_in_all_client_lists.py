from comfy.compliance import medium


@medium(
      name='rule_5_4_ensure_default_restrict_is_set_in_all_client_lists',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_5_4_ensure_default_restrict_is_set_in_all_client_lists(commands, ref):
    assert '' in commands.chk_cmd, ref
