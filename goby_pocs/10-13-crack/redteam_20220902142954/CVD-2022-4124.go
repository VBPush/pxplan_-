package exploits

import (
	"errors"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func init() {
	expJson := `{
    "Name": "Gitlab GitHub Import API Remote Command Execution Vulnerability (CVE-2022-2992)",
    "Description": "<p>Gitlab is a self managed git (version control system) project warehouse application developed by gitlab company in the United States using Ruby on rails. This program can be used to check the file content, submission history, bug list, etc. of the project.</p><p>A vulnerability exists in all versions of GitLab from 15.3 to 15.3.2, from 15.2 to 15.2.4, and from 11.10 to 15.1.6 that allows an authenticated user to achieve remote code execution by importing from the GitHub API endpoint. Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.</p>",
    "Impact": "Gitlab GitHub Import API Remote Command Execution Vulnerability (CVE-2022-2992)",
    "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://about.gitlab.com/update\">https://about.gitlab.com/update</a></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Product": "Gitlab",
    "VulType": [
        "Command Execution"
    ],
    "Tags": [
        "Command Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Gitlab GitHub Import API 远程命令执行漏洞（CVE-2022-2992）",
            "Description": "<p>GitLab是美国GitLab公司的一款使用Ruby on Rails开发的、自托管的、Git（版本控制系统）项目仓库应用程序。该程序可用于查阅项目的文件内容、提交历史、Bug列表等。</p><p>在15.3 到 15.3.2、从15.2 到15.2.4以及从 11.10 到 15.1.6 的所有版本的GitLab中存在漏洞，该漏洞允许经过身份验证的用户通过从GitHub API端点导入方式实现远程代码执行。攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">在15.3 到 15.3.2、从15.2 到15.2.4以及从 11.10 到 15.1.6 的所有版本的GitLab中存在漏洞，该漏洞允许经过身份验证的用户通过从GitHub API端点导入方式实现远程代码执行。</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">攻击者可通过该漏洞在服务器端任意执行代码，写入后门，获取服务器权限，进而控制整个web服务器。</span><br></p>",
            "Recommendation": "<p><span style=\"color: var(--primaryFont-color);\">1、官方暂未修复该漏洞，请用户联系厂商修复漏洞：</span><a href=\"https://about.gitlab.com/update\">https://about.gitlab.com/update</a><br></p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Product": "Gitlab",
            "VulType": [
                "命令执行"
            ],
            "Tags": [
                "命令执行"
            ]
        },
        "EN": {
            "Name": "Gitlab GitHub Import API Remote Command Execution Vulnerability (CVE-2022-2992)",
            "Description": "<p>Gitlab is a self managed git (version control system) project warehouse application developed by gitlab company in the United States using Ruby on rails. This program can be used to check the file content, submission history, bug list, etc. of the project.</p><p>A vulnerability exists in all versions of GitLab from 15.3 to 15.3.2, from 15.2 to 15.2.4, and from 11.10 to 15.1.6 that allows an authenticated user to achieve remote code execution by importing from the GitHub API endpoint. Attackers can use this vulnerability to execute code arbitrarily on the server side, write backdoors, obtain server permissions, and then control the entire web server.<br></p>",
            "Impact": "Gitlab GitHub Import API Remote Command Execution Vulnerability (CVE-2022-2992)",
            "Recommendation": "<p>1. There is currently no detailed solution provided, please pay attention to the manufacturer's homepage update:</p><p><a href=\"https://about.gitlab.com/update\">https://about.gitlab.com/update</a><br></p><p></p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Product": "Gitlab",
            "VulType": [
                "Command Execution"
            ],
            "Tags": [
                "Command Execution"
            ]
        }
    },
    "FofaQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "GobyQuery": "(header=\"_gitlab_session\" || banner=\"_gitlab_session\" || body=\"gon.default_issues_tracker\" || body=\"content=\\\"GitLab Community Edition\\\"\" || title=\"Sign in · GitLab\" || body=\"content=\\\"GitLab \" || body=\"<a href=\\\"https://about.gitlab.com/\\\">About GitLab\" || body=\"class=\\\"col-sm-7 brand-holder pull-left\\\"\")",
    "Author": "twcjw",
    "Homepage": "https://gitlab.com",
    "DisclosureDate": "2022-08-31",
    "References": [
        "https://about.gitlab.com/releases/2022/08/30/critical-security-release-gitlab-15-3-2-released"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "9.9",
    "CVEIDs": [
        "CVE-2022-2992"
    ],
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
            "name": "",
            "type": "input",
            "value": "",
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
    "PocId": "7279"
}`

	getSubMatchStr123sdf1134s := func(pattern string, content string) (err error, result string) {
		compile := regexp.MustCompile(pattern)
		match := compile.FindAllStringSubmatch(content, -1)
		if match != nil && len(match[0]) == 2 {
			return nil, match[0][1]
		}
		return errors.New("getSubMatchStr: nil Content"), ""
	}
	VersionVerifityfsd342234 := func(version string) bool {
		err, result := getSubMatchStr123sdf1134s("\"version\":\"(.*?)\",", version)
		if err != nil {
			return false
		}
		version = result
		version = strings.Split(version, "-")[0]
		vs := strings.Split(version, ".")
		v1, _ := strconv.Atoi(vs[0])
		v2, _ := strconv.Atoi(vs[1])
		if v1 == 11 && v2 >= 10 {
			return true
		}
		if v1 < 15 && v1 > 11 {
			return true
		}
		if v1 == 15 {
			v3, _ := strconv.Atoi(vs[2])
			if v2 == 1 && v3 < 6 {
				return true
			}
			if v2 == 2 && v3 < 4 {
				return true
			}
			if v2 == 3 && v3 < 2 {
				return true
			}
		}
		return false
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, hostinfo *httpclient.FixUrl, stepLogs *scanconfig.SingleScanConfig) bool {
			defer func() {
				if err := recover(); err != nil {
					log.Println("recovered from panic", err)
				}
			}()
			fmt.Println(hostinfo.HostInfo)
			for tem := 0; tem < 8; tem++ {
				uri := "/users/sign_in"
				req := httpclient.NewGetRequestConfig(uri)
				req.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
				req.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				req.Timeout = 5
				req.VerifyTls = false
				req.FollowRedirect = false
				resp, err := httpclient.DoHttpRequest(hostinfo, req)
				time.Sleep(2 * time.Second)
				if err != nil {
					fmt.Println(err)
				}
				Cookies := resp.Cookie
				Cookies = strings.Replace(Cookies, "request_method=;", "", 1)
				err, result1 := getSubMatchStr123sdf1134s("<meta name=\"csrf-token\" content=\"(.*?)\"", resp.Utf8Html)
				if err != nil {
					return false
				}
				username := "X" + goutils.RandomHexString(8)
				useremail := goutils.RandomHexString(8) + "@exam.org"
				userinfo := "&new_user%5Bname%5D=" + username + "&new_user%5Busername%5D=" + username + "&new_user%5Bemail%5D=" + useremail + "&new_user%5Bpassword%5D=" + username
				req1 := httpclient.NewPostRequestConfig("/users")
				req1.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
				req1.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				req1.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
				req1.Header.Store("Accept-Encoding", "gzip, deflate")
				req1.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				req1.Header.Store("Referer", "http://"+hostinfo.HostInfo+"/users/sign_in")
				req1.Header.Store("Cookie", Cookies)
				req1.Header.Store("Connection", "close")
				req1.FollowRedirect = false
				req1.VerifyTls = false
				req1.Data = "utf8=%E2%9C%93&authenticity_token=" + result1 + userinfo
				req1.Timeout = 5
				resp1, err := httpclient.DoHttpRequest(hostinfo, req1)
				reqVersion := httpclient.NewGetRequestConfig("/api/v4/version")
				reqVersion.Header.Store("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
				reqVersion.Header.Store("Content-Type", "application/x-www-form-urlencoded")
				reqVersion.Header.Store("Accept-Language", "zh-CN,zh;q=0.9")
				reqVersion.Header.Store("Accept-Encoding", "gzip, deflate")
				reqVersion.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
				reqVersion.Header.Store("Referer", "http://"+hostinfo.HostInfo+"/users/sign_up/welcome")
				reqVersion.Header.Store("Cookie", resp1.Cookie)
				reqVersion.Header.Store("Connection", "close")
				reqVersion.Timeout = 5
				reqVersion.VerifyTls = false
				reqVersion.FollowRedirect = false
				respVersion, err := httpclient.DoHttpRequest(hostinfo, reqVersion)
				if err != nil {
					return false
				}
				if tem != 7 && respVersion.StatusCode != 200 {
					continue
				}
				if VersionVerifityfsd342234(respVersion.Utf8Html) {
					return true
				}
			}
			return false
		},
		nil,
	))
}
