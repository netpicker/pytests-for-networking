import pytest
from comfy.compliance import *

@medium(
  name = 'rule_224_set_ip_address_for_logging_host',
  platform = ['cisco_ios']
)
def rule_224_set_ip_address_for_logging_host(configuration, commands, device):
    assert '' in configuration

# Remediation: hostname(config)#logging host {syslog_server}  

# References: 1. http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#
