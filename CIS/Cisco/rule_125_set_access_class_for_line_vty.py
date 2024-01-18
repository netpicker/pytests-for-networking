
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_125_set_access_class_for_line_vty,
  platform = ['cisco_ios']
)
def rule_125_set_access_class_for_line_vty(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#line vty <line -number> <ending -line-number> 

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/a1/sec -cr-a2.html#GUID -
