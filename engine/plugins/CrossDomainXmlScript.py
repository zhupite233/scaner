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
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        url = "%s://%s%s%s" % (scheme,domain,path,"crossdomain.xml")
        res, content = http.request(url, 'GET', headers=header)
        
        if res and res.has_key('status') and res['status'] == '200':
            match = re.findall(r"<(\s*)allow-access-from(\s+)domain(\s*)=(\s*)(\"|')(.+?)\5(.*?)/(\s*)>",content,re.I|re.DOTALL)
            if match and len(match) > 0:
                for row in match:
                    keyword = row[5].replace(" ","")
                    if keyword == "*":
                        detail = "发现网站的配置文件crossdomain.xml中开启了允许访问的域为任意域的功能，可能导致网站存在危险。"
                        request = getRequest(url, domain=ob['domain'])
                        response = getResponse(res, "\n".join(match))
                        output = "<%sallow-access-from%sdomain%s=%s%s%s%s%s/%s>" % (row[0],row[1],row[2],row[3],row[4],row[5],row[4],row[6],row[7])
                        result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
                        
                        return result
                    #end if
                #end for
            #end if
        #end if
        
    except Exception,e:
        logger.error("File:CrossDomainXml.py, run_domain function :%s" % (str(e)))     
    #end try
    
    return result
#end def



