import pytest
from comfy.compliance import *

@medium(
  name = 'rule_2112_set_version_2_for_ip_ssh_version',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip ssh')
)
def rule_2112_set_version_2_for_ip_ssh_version(configuration, commands, device):
    assert f'hostname#sh ip ssh' in commands.check_command,"\n# Remediation: hostname(config)#ip ssh version 2  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-170AECF1-4B5B-462A-8CC8-999DEDC45C21\n\n
