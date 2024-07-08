from comfy.compliance import medium


@medium(
      name='rule_3_6_ensure_icmp_redirects_are_set_to_disabled_on_all_untrusted_ipv4_networks',
      platform=['juniper'],
      commands=dict(chk_cmd='')
)
def rule_3_6_ensure_icmp_redirects_are_set_to_disabled_on_all_untrusted_ipv4_networks(commands, ref):
    assert '' in commands.chk_cmd, ref
