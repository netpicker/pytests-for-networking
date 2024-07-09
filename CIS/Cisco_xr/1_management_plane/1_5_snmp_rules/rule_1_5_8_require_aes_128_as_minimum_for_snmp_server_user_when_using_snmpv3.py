from comfy.compliance import low


@low(
      name='rule_1_5_8_require_aes_128_as_minimum_for_snmp_server_user_when_using_snmpv3',
      platform=['cisco_xr'],
      commands=dict(chk_cmd='')
)
def rule_1_5_8_require_aes_128_as_minimum_for_snmp_server_user_when_using_snmpv3(commands, ref):
    assert '' in commands.chk_cmd, ref
