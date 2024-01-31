import pytest
from comfy.compliance import *

@low(
  name = 'rule_2314_set_key_for_each_ntp_server',
  platform = ['cisco_ios']
)
def rule_2314_set_key_for_each_ntp_server(configuration, commands, device):
    assert 'ntp server' in configuration,"
# Remediation: hostname(config)#ntp server {<em> ntp-server_ip_address</em>}{key 
# References: 


