import pytest
from comfy.compliance import *

@low(
  name = rule_3331_set_key_chain,
  platform = ['cisco_ios']
)
def rule_3331_set_key_chain(configuration,commands,device):
    assert '' in configuration  

#Remediation: hostname(config)#key chain {<em>rip_key -chain_name</em>}  

#References: 1. http://www.cisco.com/en/US/docs/ios -xml/ios/iproute_pi/command/iri -cr-
