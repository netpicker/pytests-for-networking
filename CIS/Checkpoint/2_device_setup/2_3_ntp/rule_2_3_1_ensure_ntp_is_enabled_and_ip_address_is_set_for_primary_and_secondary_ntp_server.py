from comfy.compliance import medium


@medium(
      name='rule_2_3_1_ensure_ntp_is_enabled_and_ip_address_is_set_for_primary_and_secondary_ntp_server',
      platform=['checkpoint'],
      commands=dict(chk_cmd='')
)
def rule_2_3_1_ensure_ntp_is_enabled_and_ip_address_is_set_for_primary_and_secondary_ntp_server(commands, ref):
    assert '' in commands.chk_cmd, ref
