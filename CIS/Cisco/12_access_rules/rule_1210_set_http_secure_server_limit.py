import pytest
from comfy.compliance import *

@medium(
  name = 'rule_1210_set_http_secure_server_limit',
  platform = ['cisco_ios']
)
def rule_1210_set_http_secure_server_limit(configuration, commands, device):
    assert 'ip http secure-server' in configuration,"\n# Remediation: hostname(config)#ip http max-connections 2  \n# References: \n\n"
