from comfy.compliance import low


@low(
      name='rule_6_10_5_3_ensure_rest_is_set_to_use_pki_certificate_for_https',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_10_5_3_ensure_rest_is_set_to_use_pki_certificate_for_https(commands, ref):
    assert '' in commands.chk_cmd, ref
