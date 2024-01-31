import pytest
from comfy.compliance import *

@medium(
  name = 'rule_224_set_ip_address_for_logging_host',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh log | incl logging host')
)
def rule_224_set_ip_address_for_logging_host(configuration, commands, device):
    assert f' logging host' in commands.check_command

# Remediation: hostname(config)#logging host {syslog_server}  

# References: 1.http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#
