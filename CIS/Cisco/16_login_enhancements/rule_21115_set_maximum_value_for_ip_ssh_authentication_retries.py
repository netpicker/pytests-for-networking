import pytest
from comfy.compliance import *

@medium(
  name = 'rule_21115_set_maximum_value_for_ip_ssh_authentication_retries',
  platform = ['cisco_ios'],
  commands=dict(check_command='sh ip ssh')
)
def rule_21115_set_maximum_value_for_ip_ssh_authentication_retries(configuration, commands, device):
    assert f'hostname#sh ip ssh' in commands.check_command,"\n# Remediation: hostname(config)#ip ssh authentication-retries [<em>3</em>]  \n# References: 1.http://www.cisco.com/en/US/docs/ios-xml/ios/security/d1/sec-cr-i3.html#GUID-5BAC7A2B-0A25-400F-AEE9-C22AE08513C6\n\n
