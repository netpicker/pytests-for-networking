import pytest
from comfy.compliance import *

@medium(
  name = rule_124_create_access_list_for_use_with_line_v_ty,
  platform = ['cisco_ios']
)
def rule_124_create_access_list_for_use_with_line_v_ty(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#deny ip any any log  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/security/a 1/sec -cr-a2.html#GUID -
