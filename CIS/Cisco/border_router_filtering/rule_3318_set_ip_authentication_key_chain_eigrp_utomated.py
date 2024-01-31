import pytest
from comfy.compliance import *

@low(
  name = 'rule_3318_set_ip_authentication_key_chain_eigrp_utomated',
  platform = ['cisco_ios'],
  commands=dict(check_command='hostname#sh run int {<em>interface_name</em>} | incl key-chain')
)
def rule_3318_set_ip_authentication_key_chain_eigrp_utomated(configuration, commands, device):
    assert ' key-chain' in configuration

# Remediation: hostname(config)#interface {<em>interface_name</em>}  

# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_eigrp/command/ire-i1.html#GUID-0B344B46-5E8E-4FE2-A3E0-D92410CE5E91
