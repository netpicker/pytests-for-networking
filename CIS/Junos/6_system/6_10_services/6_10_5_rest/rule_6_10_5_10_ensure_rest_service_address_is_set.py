from comfy.compliance import medium


@medium(
      name='rule_6_10_5_10_ensure_rest_service_address_is_set',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_10_ensure_rest_service_address_is_set(commands, ref):
    assert '' in commands.chk_cmd, ref
