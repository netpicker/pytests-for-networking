
import pytest
from comfy.compliance import Source, medium

@medium(
  name = rule_212_set_no_cdp_run,
  platform = ['cisco_ios']
)
def rule_212_set_no_cdp_run(configuration,commands,device):
    assert 'hostname#show  cdp' in configuration  

#Remediation: hostname(config)#no cdp run  

#References: 1. http://www.cisco.com/en/US/docs/io s-xml/ios/cdp/command/cdp -cr-
