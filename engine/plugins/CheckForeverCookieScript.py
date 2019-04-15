#!/usr/bin/python
# -*- coding: utf-8 -*-
import datetime
import time

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
        url = "%s://%s%s" % (scheme,domain,path)
        res, content = http.request(url, headers=header)
        if res and res.has_key('status') and res['status'] == '200' and res.has_key('set-cookie') and res['set-cookie'] != '':
            set_cookie = res['set-cookie']
            match = re.findall(r"expires(\s*)=(\s*)([a-z]+), ([0-9]+)-([a-z]+)-([0-9]+) ([0-9:]+) (gmt)",set_cookie,re.I)
            if match and len(match) > 0:
                year = match[0][5]
                if len(year) == 1:
                    year = "200%s" % (year)
                elif len(year) == 2:
                    year = "20%s" % (year)
                elif len(year) == 3:
                    year = "2%s" % (year)
                elif len(year) > 4:
                    year = year[0:4]
                #end if
                gmt_time = "%s, %s-%s-%s %s GMT" % (match[0][2],match[0][3],match[0][4],year,match[0][6])
                gmt_format = "%a, %d-%b-%Y %H:%M:%S GMT"
                gmt_time_int = time.mktime(time.strptime(str(datetime.datetime.strptime(gmt_time, gmt_format)), "%Y-%m-%d %H:%M:%S"))
                if gmt_time_int > time.time() + 5*60:
                    detail = "在应用程序测试过程中，检测到在客户端的计算机上，将用户凭证或会话令牌之类的敏感会话信息存储在永久 cookie 中。"
                    request = getRequest(url, domain=ob['domain'])
                    response = getResponse(res)
                    output = set_cookie
                    result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
                #end if
            #end if
        #end if
        
    except Exception,e:
        logger.error("File:CheckForeverCookieScript.py, run_domain function :%s" % (str(e))) 
    #end try
    
    return result
#end def

