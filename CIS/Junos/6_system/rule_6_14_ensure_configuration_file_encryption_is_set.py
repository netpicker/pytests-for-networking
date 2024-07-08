from comfy.compliance import low


@low(
      name='rule_6_14_ensure_configuration_file_encryption_is_set',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_14_ensure_configuration_file_encryption_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
