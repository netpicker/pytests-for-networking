import pytest
from comfy.compliance import *

@medium(
  name = 'rule_129_set_transport_input_none_for_line_aux_0',
  platform = ['cisco_ios']
)
def rule_129_set_transport_input_none_for_line_aux_0(configuration, commands, device):
    assert 'hostname#sh line aux 0 | incl input transports' in configuration

# Remediation: hostname(config)#line aux 0  

# References: 1.http://www.cisco.com/en/US/docs/ios/termserv/command/reference/tsv_s1.html#
