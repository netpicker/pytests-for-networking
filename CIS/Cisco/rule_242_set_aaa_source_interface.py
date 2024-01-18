
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_242_set_aaa_source_interface,
  platform = ['cisco_ios']
)
def rule_242_set_aaa_source_interface(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 2. http://www.cisco.com/en/US/docs/ios -xml/ios/security/d1/sec -cr-i3.html#GUID -
