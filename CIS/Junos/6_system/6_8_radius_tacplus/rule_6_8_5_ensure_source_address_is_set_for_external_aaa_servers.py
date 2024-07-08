from comfy.compliance import medium


@medium(
      name='rule_6_8_5_ensure_source_address_is_set_for_external_aaa_servers',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_8_5_ensure_source_address_is_set_for_external_aaa_servers(commands, ref):
    assert '' in commands.chk_cmd, ref
