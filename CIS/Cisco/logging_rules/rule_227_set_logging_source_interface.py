import pytest
from comfy.compliance import *

@medium(
  name = 'rule_227_set_logging_source_interface',
  platform = ['cisco_ios']
)
def rule_227_set_logging_source_interface(configuration, commands, device):
    assert 'hostname#sh run | incl logging source' in configuration

# Remediation: hostname(config)#logging source-interface loopback 

# References: 1.http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#
