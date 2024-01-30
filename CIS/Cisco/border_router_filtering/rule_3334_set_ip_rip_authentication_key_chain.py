import pytest
from comfy.compliance import *

@low(
  name = 'rule_3334_set_ip_rip_authentication_key_chain',
  platform = ['cisco_ios']
)
def rule_3334_set_ip_rip_authentication_key_chain(configuration, commands, device):
    assert 'hostname#sh run int {<em>interface_name</em>}' in configuration

# Remediation: hostname(config)#interface {<em>interface_name</em>}  

# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_rip/command/irr-cr-rip.html#GUID-C1C84D0D-4BD0-4910-911A-ADAB458D0A84