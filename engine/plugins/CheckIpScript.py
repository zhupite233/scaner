#!/usr/bin/python
# -*- coding: utf-8 -*-


from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urlparse import urlparse


def run_url(http,ob,item):
    try:
        result = []
        if item['method'] != 'get':
            return []
        #end if
        url = item['url']
        if item['params'] != '':
            url = "%s?%s" % (url,item['params'])
        #end if
        header = {'Host': ob['domain']}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        if query:
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        detail = "检测到包含内部 IP 地址的响应。"
        res, content = http.request(new_url, headers=header)
        if res and res.has_key('status') and res['status'] == '200' and res.has_key('content-type') and res['content-type'] != '' and content != '' and (content.find('10.') > 0 or content.find('172.') > 0 or content.find('192.168.') > 0): 
            temp = content.replace("\r\n","\n").split("\n")
            output = []
            for row in temp:
                if  row.find('10.') < 0 and row.find('172.') < 0 and row.find('192.168.') < 0 and checkIpv6Inner(row) == False:
                    continue
                else:                  
                    if checkIpv6Inner(row):
                        row = row.upper()
                        match = re.findall(u"((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?",row,re.I)
                        if match and len(match) > 0:
                            if match and len(match):
                                inner_ip = match[0][0]
                                if inner_ip[:3] == 'FEC':
                                    if ob['domain'].find(inner_ip) >= 0 or inner_ip == ob['ip']:
                                        continue
                                    if inner_ip in output:
                                        continue
                                    else:
                                        output.append(inner_ip)
                    else:
                        match = re.findall(r"[^0-9.](10|172|192)\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])\.(\d{1,2}|1\d\d|2[0-4]\d|25[0-5])[^0-9.]",row,re.I)
                        if match and len(match) > 0:
                            inner_ip = "%s.%s.%s.%s" % (match[0][0],match[0][1],match[0][2],match[0][3])
                            if inner_ip == ob['domain'].split(':')[0] or inner_ip == ob['ip']:
                                continue
                            #end if
                            if inner_ip in output:
                                continue
                            else:
                                output.append(inner_ip)
                            #end if
                        #end if
                    #end if
            #end for
            if len(output) > 0:
                request = getRequest(url, domain=ob['domain'])
                response = getResponse(res, "\n".join(output))
                result.append(getRecord(ob,new_url,ob['level'],detail,request,response,"\n".join(output)))
            #end if
        #end if
        
        return result
    except Exception,e:
        logger.error("File:CheckIpScript.py, run_url function :" + str(e))
        return []
    #end try    
#end def

