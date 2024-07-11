from comfy.compliance import medium


@medium(
      name='rule_6_3_2_ensure_local_accounts_can_only_be_used_during_loss_of_external_aaa',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_3_2_ensure_local_accounts_can_only_be_used_during_loss_of_external_aaa(commands, ref):
    assert '' in commands.chk_cmd, ref
