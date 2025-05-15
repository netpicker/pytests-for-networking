from comfy import medium


@medium(
    name='rule_cis_1_1_dns_server_configured',
    platform=['fortinet'],
)
def rule_cis_1_1_dns_server_configured(configuration, commands, device):
    dns_output = device.cli('show system dns')
    assert 'set primary' in dns_output.lower(), "Primary DNS server is not configured"
