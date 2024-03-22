import re
from comfy.compliance import low


@low(
    name='rule_112_configure_an_authorized_ip_address_for_ntp_server',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show time')
)
def rule_112_configure_an_authorized_ip_address_for_ntp_server(commands, ref):
    ipv4_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    assert re.search(ipv4_regex, commands.chk_cmd), ref
