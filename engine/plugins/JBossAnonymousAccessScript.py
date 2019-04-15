#!/usr/bin/env python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    list = []
    try:
        domain = ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        detail = u"JBoss是全世界开发者共同努力的成果，一个基于J2EE的开放源代码的应用服务器，JBoss允许匿名访问，攻击者可利用此执行远程代码，导致服务器直接被上传WebShell。"
        detail = detail.encode('utf8')

        url = "%s://%s/" % (ob['scheme'],domain)
        url += "jmx-console/HtmlAdaptor"
        res, content = http.request(url, 'GET', headers=header)
        if res['status'] == '200' and content.find('MX Agent View') >= 0:
            request = getRequest(url, domain=ob['domain'])
            response = getResponse(res)
            list.append(getRecord(ob,url,ob['level'],detail,request,response))
        else:
            url = "%s://%s:8080/" % (ob['scheme'],domain)
            url += "jmx-console/HtmlAdaptor"
            res, content = http.request(url, 'GET', headers=header)
            if res['status'] == '200' and content.find("MX Agent View") >= 0:
                request = getRequest(url, domain=ob['domain'])
                response = getResponse(res, content, "MX Agent View")
                list.append(getRecord(ob,url,ob['level'],detail,request,response))
            #end if
        #end if
    except Exception,e:
        logger.error("File:JBossAnonymousAccessScript.py, run_domain function :" + str(e))
    #end try
    
    return list
#end def




            
        
        
        
        
        
