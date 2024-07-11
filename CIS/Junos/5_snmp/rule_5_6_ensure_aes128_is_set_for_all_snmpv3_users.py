from comfy.compliance import low


@low(
      name='rule_5_6_ensure_aes128_is_set_for_all_snmpv3_users',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_5_6_ensure_aes128_is_set_for_all_snmpv3_users(commands, ref):
    assert '' in commands.chk_cmd, ref
