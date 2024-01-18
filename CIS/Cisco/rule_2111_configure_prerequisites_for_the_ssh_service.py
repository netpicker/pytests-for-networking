
import pytest
from comfy.compliance import Source, low

@low(
  name = rule_2111_configure_prerequisites_for_the_ssh_service,
  platform = ['cisco_ios']
)
def rule_2111_configure_prerequisites_for_the_ssh_service(configuration,commands,device):
    assert '' in configuration  

#Remediation: 

#References: 
