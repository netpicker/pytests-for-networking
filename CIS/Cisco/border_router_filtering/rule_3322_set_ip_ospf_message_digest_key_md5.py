import pytest
from comfy.compliance import *

@low(
  name = 'rule_3322_set_ip_ospf_message_digest_key_md5',
  platform = ['cisco_ios']
)
def rule_3322_set_ip_ospf_message_digest_key_md5(configuration, commands, device):
    assert 'hostname#sh run int {<em>interface</em>}' in configuration

# Remediation: hostname(config)#interface {<em>interface_name</em>}  

# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_ospf/command/ospf-i1.html#GUID-939C79FF-8C09-4D5A-AEB5-DAF25038CA18
