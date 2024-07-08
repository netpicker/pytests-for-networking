from comfy.compliance import medium


@medium(
      name='rule_6_22_ensure_icmp_redirects_are_disabled_for_ipv6',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_6_22_ensure_icmp_redirects_are_disabled_for_ipv6(commands, ref):
    assert '' in commands.chk_cmd, ref
