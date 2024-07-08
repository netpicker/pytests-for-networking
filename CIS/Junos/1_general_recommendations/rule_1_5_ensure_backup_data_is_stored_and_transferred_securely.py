from comfy.compliance import medium


@medium(
      name='rule_1_5_ensure_backup_data_is_stored_and_transferred_securely',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_1_5_ensure_backup_data_is_stored_and_transferred_securely(commands, ref):
    assert '' in commands.chk_cmd, ref
