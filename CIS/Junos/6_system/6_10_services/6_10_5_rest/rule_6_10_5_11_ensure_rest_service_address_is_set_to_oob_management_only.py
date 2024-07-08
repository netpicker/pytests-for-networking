from comfy.compliance import low


@low(
      name='rule_6_10_5_11_ensure_rest_service_address_is_set_to_oob_management_only',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_11_ensure_rest_service_address_is_set_to_oob_management_only(commands, ref):
    assert '' in commands.chk_cmd, ref
