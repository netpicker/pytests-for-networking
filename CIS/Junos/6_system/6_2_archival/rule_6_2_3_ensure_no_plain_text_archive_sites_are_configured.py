from comfy.compliance import medium


@medium(
      name='rule_6_2_3_ensure_no_plain_text_archive_sites_are_configured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_2_3_ensure_no_plain_text_archive_sites_are_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
