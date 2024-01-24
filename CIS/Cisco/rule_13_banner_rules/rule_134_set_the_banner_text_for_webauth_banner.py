import pytest
from comfy.compliance import *

@medium(
  name = rule_134_set_the_banner_text_for_webauth_banner,
  platform = ['cisco_ios']
)
def rule_134_set_the_banner_text_for_webauth_banner(configuration,commands,device):
    assert 'hostname#show ip admission auth -proxy-banner http' in configuration  

#Remediation: hostname(config)#ip  admission auth -proxy-banner http {banner -text | filepath}  

#References: 
