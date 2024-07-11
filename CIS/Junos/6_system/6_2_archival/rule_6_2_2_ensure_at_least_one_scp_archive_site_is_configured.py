from comfy.compliance import low


@low(
      name='rule_6_2_2_ensure_at_least_one_scp_archive_site_is_configured',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_2_2_ensure_at_least_one_scp_archive_site_is_configured(commands, ref):
    assert '' in commands.chk_cmd, ref
