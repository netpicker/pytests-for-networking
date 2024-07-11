from comfy.compliance import medium


@medium(
      name='rule_6_10_10_ensure_unused_dhcp_service_is_not_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_10_ensure_unused_dhcp_service_is_not_set(commands, ref):
    assert '' in commands.chk_cmd, ref
