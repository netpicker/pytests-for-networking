from comfy.compliance import medium


@medium(
      name='rule_5_2_ensure_snmpv1_2_are_set_to_read_only',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_5_2_ensure_snmpv1_2_are_set_to_read_only(commands, ref):
    assert '' in commands.chk_cmd, ref
