import pytest
from comfy.compliance import *

@medium(
  name = 'rule_125_set_access_class_for_line_vty',
  platform = ['cisco_ios']
)
def rule_125_set_access_class_for_line_vty(configuration, commands, device):
    assert 'hostname#sh run | sec vty <line-number> <ending-line-number>' in configuration

# Remediation: hostname(config)#line vty <line-number> <ending-line-number> 

# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/a1/sec-cr-a2.html#GUID-FB9BC58A-F00A-442A-8028-1E9E260E54D3