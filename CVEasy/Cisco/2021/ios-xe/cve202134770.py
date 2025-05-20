{
    "containers": {
        "cna": {
            "affected": [
                {
                    "product": "Cisco IOS XE Software",
                    "vendor": "Cisco",
                    "versions": [
                        {
                            "status": "affected",
                            "version": "n/a"
                        }
                    ]
                }
            ],
            "datePublic": "2021-09-22T00:00:00",
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A vulnerability in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to execute arbitrary code with administrative privileges or cause a denial of service (DoS) condition on an affected device. The vulnerability is due to a logic error that occurs during the validation of CAPWAP packets. An attacker could exploit this vulnerability by sending a crafted CAPWAP packet to an affected device. A successful exploit could allow the attacker to execute arbitrary code with administrative privileges or cause the affected device to crash and reload, resulting in a DoS condition."
                }
            ],
            "exploits": [
                {
                    "lang": "en",
                    "value": "The Cisco Product Security Incident Response Team (PSIRT) is not aware of any public announcements or malicious use of the vulnerability that is described in this advisory."
                }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "attackComplexity": "LOW",
                        "attackVector": "NETWORK",
                        "availabilityImpact": "HIGH",
                        "baseScore": 10,
                        "baseSeverity": "CRITICAL",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "privilegesRequired": "NONE",
                        "scope": "CHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "version": "3.1"
                    }
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-122",
                            "description": "CWE-122",
                            "lang": "en",
                            "type": "CWE"
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "dateUpdated": "2021-09-23T02:27:02",
                "orgId": "d1c1063e-7a18-46af-9102-31f8928bc633",
                "shortName": "cisco"
            },
            "references": [
                {
                    "name": "20210922 Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution Vulnerability",
                    "tags": [
                        "vendor-advisory",
                        "x_refsource_CISCO"
                    ],
                    "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-rce-LYgj8Kf"
                }
            ],
            "source": {
                "advisory": "cisco-sa-ewlc-capwap-rce-LYgj8Kf",
                "defect": [
                    [
                        "CSCvw08884"
                    ]
                ],
                "discovery": "INTERNAL"
            },
            "title": "Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution Vulnerability",
            "x_legacyV4Record": {
                "CVE_data_meta": {
                    "ASSIGNER": "psirt@cisco.com",
                    "DATE_PUBLIC": "2021-09-22T16:00:00",
                    "ID": "CVE-2021-34770",
                    "STATE": "PUBLIC",
                    "TITLE": "Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution Vulnerability"
                },
                "affects": {
                    "vendor": {
                        "vendor_data": [
                            {
                                "product": {
                                    "product_data": [
                                        {
                                            "product_name": "Cisco IOS XE Software",
                                            "version": {
                                                "version_data": [
                                                    {
                                                        "version_value": "n/a"
                                                    }
                                                ]
                                            }
                                        }
                                    ]
                                },
                                "vendor_name": "Cisco"
                            }
                        ]
                    }
                },
                "data_format": "MITRE",
                "data_type": "CVE",
                "data_version": "4.0",
                "description": {
                    "description_data": [
                        {
                            "lang": "eng",
                            "value": "A vulnerability in the Control and Provisioning of Wireless Access Points (CAPWAP) protocol processing of Cisco IOS XE Software for Cisco Catalyst 9000 Family Wireless Controllers could allow an unauthenticated, remote attacker to execute arbitrary code with administrative privileges or cause a denial of service (DoS) condition on an affected device. The vulnerability is due to a logic error that occurs during the validation of CAPWAP packets. An attacker could exploit this vulnerability by sending a crafted CAPWAP packet to an affected device. A successful exploit could allow the attacker to execute arbitrary code with administrative privileges or cause the affected device to crash and reload, resulting in a DoS condition."
                        }
                    ]
                },
                "exploit": [
                    {
                        "lang": "en",
                        "value": "The Cisco Product Security Incident Response Team (PSIRT) is not aware of any public announcements or malicious use of the vulnerability that is described in this advisory."
                    }
                ],
                "impact": {
                    "cvss": {
                        "baseScore": "10.0",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "version": "3.0"
                    }
                },
                "problemtype": {
                    "problemtype_data": [
                        {
                            "description": [
                                {
                                    "lang": "eng",
                                    "value": "CWE-122"
                                }
                            ]
                        }
                    ]
                },
                "references": {
                    "reference_data": [
                        {
                            "name": "20210922 Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution Vulnerability",
                            "refsource": "CISCO",
                            "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-rce-LYgj8Kf"
                        }
                    ]
                },
                "source": {
                    "advisory": "cisco-sa-ewlc-capwap-rce-LYgj8Kf",
                    "defect": [
                        [
                            "CSCvw08884"
                        ]
                    ],
                    "discovery": "INTERNAL"
                }
            }
        },
        "adp": [
            {
                "providerMetadata": {
                    "orgId": "af854a3a-2127-422b-91ae-364da2661108",
                    "shortName": "CVE",
                    "dateUpdated": "2024-08-04T00:19:48.166Z"
                },
                "title": "CVE Program Container",
                "references": [
                    {
                        "name": "20210922 Cisco IOS XE Software for Catalyst 9000 Family Wireless Controllers CAPWAP Remote Code Execution Vulnerability",
                        "tags": [
                            "vendor-advisory",
                            "x_refsource_CISCO",
                            "x_transferred"
                        ],
                        "url": "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-rce-LYgj8Kf"
                    }
                ]
            },
            {
                "metrics": [
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "timestamp": "2024-11-07T21:55:53.858236Z",
                                "id": "CVE-2021-34770",
                                "options": [
                                    {
                                        "Exploitation": "none"
                                    },
                                    {
                                        "Automatable": "yes"
                                    },
                                    {
                                        "Technical Impact": "total"
                                    }
                                ],
                                "role": "CISA Coordinator",
                                "version": "2.0.3"
                            }
                        }
                    }
                ],
                "title": "CISA ADP Vulnrichment",
                "providerMetadata": {
                    "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "shortName": "CISA-ADP",
                    "dateUpdated": "2024-11-07T21:57:58.797Z"
                }
            }
        ]
    },
    "cveMetadata": {
        "assignerOrgId": "d1c1063e-7a18-46af-9102-31f8928bc633",
        "assignerShortName": "cisco",
        "cveId": "CVE-2021-34770",
        "datePublished": "2021-09-23T02:27:02.101374Z",
        "dateReserved": "2021-06-15T00:00:00",
        "dateUpdated": "2024-11-07T21:57:58.797Z",
        "state": "PUBLISHED"
    },
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1"
}# Placeholder for CVE script

from comfy import high



@high(
    name='rule_cve202134770',
    platform=['cisco_xe'],
    commands=dict(
        show_version='show version',
        check_platform='show inventory | include Chassis',
        check_capwap='show running-config | include ap capwap|wireless management'
    ),
)
def rule_cve202134770(configuration, commands, device, devices):
    """
    This rule checks for CVE-2021-34770 vulnerability in Cisco IOS XE Software for Catalyst 9000
    Family Wireless Controllers. A vulnerability in the CAPWAP protocol processing could allow an
    unauthenticated, remote attacker to execute arbitrary code with administrative privileges or
    cause a denial of service condition through malformed CAPWAP packets.
    """
    # Extract the version information from the command output
    version_output = commands.show_version

    # Check if device is running IOS XE software
    if 'IOS XE Software' not in version_output:
        return

    # Check if this is a Catalyst 9000 Series Wireless Controller
    platform_output = commands.check_platform
    vulnerable_platforms = [
        'C9800', 'Catalyst 9800',
        'C9K-WLC', 'C9K Wireless Controller'
    ]
    is_wireless_controller = any(platform in platform_output for platform in vulnerable_platforms)

    if not is_wireless_controller:
        return

    # Check for CAPWAP configuration
    capwap_config = commands.check_capwap

    # Check if wireless management/CAPWAP is enabled
    wireless_enabled = any(feature in capwap_config for feature in [
        'ap capwap',
        'wireless management'
    ])

    # Device is vulnerable if wireless management is enabled on a Cat9K WLC
    is_vulnerable = wireless_enabled

    # Assert that the device is not vulnerable
    assert not is_vulnerable, (
        f"Device {device.name} is potentially vulnerable to CVE-2021-34770. "
        "The device is a Catalyst 9000 Family Wireless Controller with CAPWAP enabled, which could allow "
        "an unauthenticated remote attacker to execute arbitrary code with administrative privileges or "
        "cause a denial of service condition through malformed CAPWAP packets. "
        "For more information, see"
        "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ewlc-capwap-rce-LYgj8Kf"
    )
