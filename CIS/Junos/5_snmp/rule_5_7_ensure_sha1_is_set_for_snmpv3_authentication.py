from comfy.compliance import low


@low(
      name='rule_5_7_ensure_sha1_is_set_for_snmpv3_authentication',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_5_7_ensure_sha1_is_set_for_snmpv3_authentication(commands, ref):
    assert '' in commands.chk_cmd, ref
