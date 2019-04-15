#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_domain(http,ob):
    result = []
    try:
        scheme = ob['scheme']
        domain = ob['domain']
        path = ob['path']
        source_ip = ob.get('source_ip')
        header = {'Host': domain}
        if source_ip:
            domain = source_ip
        url = "%s://%s%s%s" % (scheme,domain,path,"robots.txt")
        res, content = http.request(url, headers=header)
        
        if res and res.has_key('status') and res['status'] == '200' and res.has_key('content-type') and res['content-type'] != '' and content != "":
            content_list = content.splitlines()
            for sub_content in content_list:
                if sub_content.find(':') > 0:
                    k,v = sub_content.split(':')
                    if k == 'Disallow'and (v != '/' or v != '*'):
                        detail = "robots.txt可能泄露敏感路径。"
                        request = getRequest(url, domain=ob['domain'])
                        response = getResponse(res)
                        if len(content) > 200:
                            output = "%s......" % (content[0:200])
                        else:
                            output = content
                        #end if
                        result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
                        break

                    #end if
                #end if
    except Exception,e:
        logger.error("File:CheckRobotsScript.py, run_domain function :%s" % (str(e)))   
    #end try
    
    return result
#end def



