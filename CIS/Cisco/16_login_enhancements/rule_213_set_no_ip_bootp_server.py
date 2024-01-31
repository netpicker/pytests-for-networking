import pytest
from comfy.compliance import *

@medium(
  name = 'rule_213_set_no_ip_bootp_server',
  platform = ['cisco_ios']
)
def rule_213_set_no_ip_bootp_server(configuration, commands, device):
    assert 'bootp' in configuration,"\n# Remediation: hostname(config)#ip dhcp bootp ignore  \n# References: \n\n
