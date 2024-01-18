
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_122_set_transport_input_ssh_for_line_vty_connections,
  platform = ['cisco_ios']
)
def rule_122_set_transport_input_ssh_for_line_vty_connections(configuration,commands,device):
    assert 'hostname#show running -config | sec vty' in configuration  

#Remediation: hostname(config)#line vty <line -number> <ending -line-number> 

#References: 1. http://www.cisco.com/en/US/docs/ios/termserv/command/reference/tsv_s1.html#
