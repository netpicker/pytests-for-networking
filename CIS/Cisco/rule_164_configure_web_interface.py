
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_164_configure_web_interface,
  platform = ['cisco_ios']
)
def rule_164_configure_web_interface(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
