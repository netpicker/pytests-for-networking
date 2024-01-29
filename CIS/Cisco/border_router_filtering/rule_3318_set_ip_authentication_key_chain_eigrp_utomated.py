import pytest
from comfy.compliance import *

@low(
  name = 'rule_3318_set_ip_authentication_key_chain_eigrp_utomated',
  platform = ['cisco_ios']
)
def rule_3318_set_ip_authentication_key_chain_eigrp_utomated(configuration, commands, device):
    assert 'hostname#sh run int {<em>interface_name</em>} | incl key-chain' in configuration

# Remediation: hostname(config)#interface {<em>interface_name</em>}  

# References: 2. http://www.cisco.com/en/U S/docs/ios-xml/ios/iproute_eigrp/command/ire -
