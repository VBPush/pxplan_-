package exploits

import (
	"context"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/jsonvul/protocols"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
    "Description": "<p>VNC is a screen sharing and remote operation software using RFB protocol. This software can send keyboard and mouse movements and real-time screen images through the network. VNC has nothing to do with the operating system, so it can be used across platforms, for example, you can use Windows to connect to a Linux computer, and vice versa. Even in a computer without a client program installed, as long as there is a browser that supports JAVA, it can be used.</p><p>The product has weak passwords, and attackers can use the 123456 password to enter the system, view system information, and modify system configuration, which affects the use of users.</p>",
    "Product": "VNC",
    "Homepage": "https://www.realvnc.com/en/",
    "DisclosureDate": "2020-08-04",
    "Author": "14m3ta7k",
    "FofaQuery": "(protocol=\"vnc\" || body=\"<APPLET code=VncViewer.class archive=VncViewer.jar\")",
    "Level": "2",
    "CveID": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "Tags": [
        "Default Password"
    ],
    "VulType": [
        "Default Password"
    ],
    "Impact": "<p>The product has weak passwords, and attackers can use the 123456 password to enter the system, view system information, and modify system configuration, which affects the use of users.</p>",
    "Recommendation": "<p>1. Modify the empty password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>  2. If it is not necessary, it is forbidden to access the service from the public network.</p><p>  3. Set access policies and whitelist access through security devices such as firewalls.</p>",
    "References": [
        "https://fofa.so/"
    ],
    "HasExp": false,
    "ExpParams": [],
    "is0day": false,
    "ExpTips": {
        "type": "Tips",
        "content": ""
    },
    "ScanSteps": [
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
            "SetVariable": [
                "output|lastbody||"
            ]
        }
    ],
    "Posttime": "2021-01-30 14:39:11",
    "fofacli_version": "3.10.8",
    "fofascan_version": "0.1.16",
    "status": "2",
    "GobyQuery": "(protocol=\"vnc\" || body=\"<APPLET code=VncViewer.class archive=VncViewer.jar\")",
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
    "CVEIDs": [],
    "Translation": {
        "CN": {
            "Name": "VNC 远程桌面系统默认口令漏洞",
            "Product": "VNC",
            "Description": "<p>VNC为一种使用RFB协议的屏幕画面分享及远程操作软件。此软件借由网络，可发送键盘与鼠标的动作及即时的屏幕画面。VNC与操作系统无关，因此可跨平台使用，例如可用Windows连线到某Linux的电脑，反之亦同。甚至在没有安装客户端程序的电脑中，只要有支持JAVA的浏览器，都可以使用。<br></p><p>VNC产品存在弱口令，攻击者可利用123456密码进入系统，查看系统信息，修改系统配置，影响用户使用。<br></p>",
            "Recommendation": "<p>1、修改口令，密码最好包含大小写字母、数字和特殊字符等，且位数大于8位。</p><p>2、如非必要，禁止公网访问该服务。</p><p>3、通过防火墙等安全设备设置访问策略，设置白名单访问。</p>",
            "Impact": "<p>VNC产品存在弱口令，攻击者可利用123456密码进入系统，查看系统信息，修改系统配置，影响用户使用。<br></p>",
            "VulType": [
                "默认口令"
            ],
            "Tags": [
                "默认口令"
            ]
        },
        "EN": {
            "Name": "VNC remote desktop system default password vulnerability",
            "Product": "VNC",
            "Description": "<p>VNC is a screen sharing and remote operation software using RFB protocol. This software can send keyboard and mouse movements and real-time screen images through the network. VNC has nothing to do with the operating system, so it can be used across platforms, for example, you can use Windows to connect to a Linux computer, and vice versa. Even in a computer without a client program installed, as long as there is a browser that supports JAVA, it can be used.<br></p><p>The product has weak passwords, and attackers can use the 123456 password to enter the system, view system information, and modify system configuration, which affects the use of users.</p>",
            "Recommendation": "<p>1. Modify the empty password. The password should preferably contain uppercase and lowercase letters, numbers and special characters, and the number of digits is greater than 8.</p><p>&nbsp; 2. If it is not necessary, it is forbidden to access the service from the public network.</p><p>&nbsp; 3. Set access policies and whitelist access through security devices such as firewalls.</p>",
            "Impact": "<p>The product has weak passwords, and attackers can use the 123456 password to enter the system, view system information, and modify system configuration, which affects the use of users.</p>",
            "VulType": [
                "Default Password"
            ],
            "Tags": [
                "Default Password"
            ]
        }
    },
    "Name": "VNC remote desktop system default password vulnerability",
    "Is0day": false,
    "CVSSScore": "7.3",
    "PocId": "7410"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			ok, _ := protocols.VNCCheck(context.Background(), u.HostInfo, "123456", ss.ScannerConfig)
			ss.VulURL = fmt.Sprintf("vnc://:%s@%s","123456", u.HostInfo)
			return ok
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			return expResult
		},
	))
}
