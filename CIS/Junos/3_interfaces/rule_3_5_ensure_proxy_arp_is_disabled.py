from comfy.compliance import low


@low(
      name='rule_3_5_ensure_proxy_arp_is_disabled',
      platform=['juniper'],
      commands=dict(chk_cmd='show configuration interfaces | match "proxy-arp" | count')
)
def rule_3_5_ensure_proxy_arp_is_disabled(commands, ref):
    assert commands.chk_cmd.strip() == "0", ref
