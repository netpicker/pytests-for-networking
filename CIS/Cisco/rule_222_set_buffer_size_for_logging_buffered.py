
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_222_set_buffer_size_for_logging_buffered,
  platform = ['cisco_ios']
)
def rule_222_set_buffer_size_for_logging_buffered(configuration,commands,device):
    assert 'logging buffered' in configuration  

#Remediation: hostname(config)#logging buffered [<em>log_buffer_size</em>]  

#References: 1. http://www.cisco.com/en/US/docs/ios/netmgmt/command/reference/nm_09.html#
