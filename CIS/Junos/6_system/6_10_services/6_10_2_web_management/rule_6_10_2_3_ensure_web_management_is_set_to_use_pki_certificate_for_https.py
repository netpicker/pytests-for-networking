from comfy.compliance import low


@low(
      name='rule_6_10_2_3_ensure_web_management_is_set_to_use_pki_certificate_for_https',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_10_2_3_ensure_web_management_is_set_to_use_pki_certificate_for_https(commands, ref):
    assert '' in commands.chk_cmd, ref
