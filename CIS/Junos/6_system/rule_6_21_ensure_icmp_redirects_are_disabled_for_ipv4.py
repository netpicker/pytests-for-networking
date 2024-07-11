from comfy.compliance import medium


@medium(
      name='rule_6_21_ensure_icmp_redirects_are_disabled_for_ipv4',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_6_21_ensure_icmp_redirects_are_disabled_for_ipv4(commands, ref):
    assert '' in commands.chk_cmd, ref
