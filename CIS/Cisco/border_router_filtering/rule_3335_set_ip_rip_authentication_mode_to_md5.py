import pytest
from comfy.compliance import *

@low(
  name = 'rule_3335_set_ip_rip_authentication_mode_to_md5',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh run int <<em>interface</em>>')
)
def rule_3335_set_ip_rip_authentication_mode_to_md5(configuration, commands, device):
    assert 'hostname#sh run int <<em>interface</em>>' in configuration

# Remediation: hostname(config)#interface <<em>interface_name</em>>  

# References: 2.http://www.cisco.com/en/US/docs/ios-xml/ios/iproute_rip/command/irr-cr-rip.html#GUID-47536344-60DC-4D30-9E03-94FF336332C7
