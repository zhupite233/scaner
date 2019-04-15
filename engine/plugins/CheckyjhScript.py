#!/usr/bin/env python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    '''
    ASP一句话木马检测
    '''
    list = []
    try:
        domain = ob['domain']
        header = {'Host': domain}
        detail = u''
        detail = detail.encode('utf8')
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        urltest = "%s://%s%s%s" % (ob['scheme'],domain,ob['path'],"UserFiles/1.asp;1(1).jpg")
        urltestFile = "%s://%s%s%s" % (ob['scheme'],domain,ob['path'],"UserFiles/File/1.asp;1(1).jpg")
        urltestImage = "%s://%s%s%s" % (ob['scheme'],domain,ob['path'],"UserFiles/Image/1.asp;1(1).jpg")
        
        r, c = http.request(urltest, 'GET', headers=header)
        r1, c1 = http.request(urltestFile, 'GET', headers=header)
        r2, c2 = http.request(urltestImage, 'GET', headers=header)
        if r['status']=='500' and (c.lower().find("execute request")>=0 or c.lower().find("GIF89a")>=0):
            request = getRequest(urltest, domain=ob['domain'])
            response = getResponse(r, c, keywords='(execute request|GIF89a)')
            list.append(getRecord(ob,urltest,ob['level'],detail,request,response))
        if r['status']=='200' and (c.lower().find("eval request")>=0 or c.lower().find('execute request')>=0):
            request = getRequest(urltest, domain=ob['domain'])
            response = getResponse(r, c, '(eval request|execute request)')
            list.append(getRecord(ob,urltest,ob['level'],detail,request,response))
        if r1['status']=='500' and (c1.lower().find("execute request")>=0 or c1.lower().find("GIF89a")>=0):
            request = getRequest(urltestFile, domain=ob['domain'])
            response = getResponse(r1, c1, '(execute request|GIF89a)')
            list.append(getRecord(ob,urltestFile,ob['level'],detail,request,response))
        if r1['status']=='200' and (c1.lower().find("eval request")>=0 or c1.lower().find('execute request')>=0):
            request = getRequest(urltestFile, domain=ob['domain'])
            response = getResponse(r1, c1, '(eval request|execute request)')
            list.append(getRecord(ob,urltestFile,ob['level'],detail,request,response))
        if r2['status']=='500' and (c2.lower().find("execute request")>=0 or c2.lower().find("GIF89a")>=0):
            request = getRequest(urltestImage, domain=ob['domain'])
            response = getResponse(r2, c2, '(execute request|GIF89a)')
            list.append(getRecord(ob,urltestImage,ob['level'],detail,request,response))
        if r2['status']=='200' and (c2.lower().find("eval request")>=0 or c2.lower().find('execute request')>=0):
            request = getRequest(urltestImage, domain=ob['domain'])
            response = getResponse(r2, c2, '(eval request|execute request)')
            list.append(getRecord(ob,urltestImage,ob['level'],detail,request,response))
    except Exception,e:
        logger.error("File:checkyjhscript.py, run_domain function :" + str(e))
        
    #end try
    
    return list
#end def

