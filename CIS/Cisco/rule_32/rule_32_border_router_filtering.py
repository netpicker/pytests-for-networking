import pytest
from comfy.compliance import *

@low(
  name = rule_32_border_router_filtering,
  platform = ['cisco_ios']
)
def rule_32_border_router_filtering(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
