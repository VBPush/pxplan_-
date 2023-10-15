package exploits

import "git.gobies.org/goby/goscanner/goutils"

func init() {
	expJson := `{
    "Name": "Docker remote api未授权访问",
    "Description": "Docker remote api未授权访问",
    "Product": "Docker",
    "Homepage": "https://www.docker.com/",
    "DisclosureDate": "2016-05-28",
    "Author": "shenqisimao@163.com",
    "FofaQuery": "protocol=\"docker\"",
    "Level": "3",
    "CveID": "",
    "Tags": [
        "目录遍历"
    ],
    "VulType": [
        "目录遍历"
    ],
    "Impact": "<p>黑客可以获取容器的敏感信息，进而控制容器 </p>",
    "Recommendation": "<p>官⽅暂未修复该漏洞，请⽤户联系⼚商修复漏洞：<a href=\"https://www.docker.com/\">https://www.docker.com/</a></p><p>1、部署Web应⽤防⽕墙，对数据库操作进⾏监控。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
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
                "uri": "/version",
                "follow_redirect": false,
                "header": {
                    "TestHead": "TestValue"
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
                        "bz": "undefined"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "ApiVersion",
                        "bz": "undefined"
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "KernelVersion",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "GoVersion",
                        "bz": ""
                    }
                ]
            },
            "SetVariable": []
        }
    ],
    "Posttime": "2019-10-25 10:13:54",
    "fofacli_version": "3.10.7",
    "fofascan_version": "0.1.16",
    "status": "",
    "CNNVD": [],
    "CNVD": [],
    "CVSS": "9.8",
    "GobyQuery": "protocol=\"docker\"",
    "PocId": "7420"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
