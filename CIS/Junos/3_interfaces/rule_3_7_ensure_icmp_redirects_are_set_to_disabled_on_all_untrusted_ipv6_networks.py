from comfy.compliance import medium


@medium(
      name='rule_3_7_ensure_icmp_redirects_are_set_to_disabled_on_all_untrusted_ipv6_networks',
      platform=['juniper_junos'],
      commands=dict(chk_cmd='')
)
def rule_3_7_ensure_icmp_redirects_are_set_to_disabled_on_all_untrusted_ipv6_networks(commands, ref):
    assert '' in commands.chk_cmd, ref
