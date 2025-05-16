from comfy.compliance import medium


@medium(
    name='rule_111_configure_an_authorized_ip_address_for_logging_syslog_host',
    platform=['cisco_wlc'],
    commands=dict(chk_cmd='show logging')
)
def rule_111_configure_an_authorized_ip_address_for_logging_syslog_host(commands, ref):
    assert 'Host 0' in commands.chk_cmd, ref
