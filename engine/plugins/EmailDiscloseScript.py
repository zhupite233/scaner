#!/usr/bin/python
# -*- coding: utf-8 -*-
import urlparse

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    try:
        result = []

        if item.get('method') != 'get':
            return []
        header = {'Host': ob['domain']}
        url = item['url']
        url_parse = urlparse.urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if query:
            new_url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            new_url = "%s://%s%s" % (scheme, domain, path)
        if item.get('params'):
            new_url = "%s?%s" % (new_url, item['params'])
        res, content = http.request(new_url, 'GET', headers=header)
        if res and res.get('status') == '200':
            if re.search(r"\b[\w\-]{1,50}@[\w\-]{1,20}(\.[\w\-]+){1,5}\b", content, re.M):
                output = re.findall(r"\b[\w\-]{1,50}@[\w\-]{1,20}(?:\.[\w\-]+){1,5}\b", content, re.M)
                output = list(set(output))
                request = getRequest(new_url, domain=ob['domain'])
                response = getResponse(res)
                detail = "检测到邮件信息，可能导致信息泄露: %s" % ", ".join(output)
                result.append(getRecord(ob,url,ob['level'],detail,request,response,"\n".join(output)))
        return result
    except Exception, e:
        logger.error("File:EmailDiscloseScript.py, run_url function :%s" % (str(e)))
        return []
#
# def run_url(http,ob,item):
#     try:
#         result = []
#
#         if item['method'] != 'get':
#             return []
#         #end if
#         header = {'Host': ob['domain']}
#         url = item['url']
#         url_parse = urlparse.urlparse(url)
#         scheme = url_parse.scheme
#         domain = url_parse.netloc
#         path = url_parse.path
#         query = url_parse.query
#         source_ip = ob.get('source_ip')
#         if source_ip:
#             domain = source_ip
#         if query:
#             url = "%s://%s%s?%s" % (scheme, domain, path, query)
#         else:
#             url = "%s://%s%s" % (scheme, domain, path)
#         if item.get('params'):
#             url = "%s?%s" % (url, item['params'])
#         #end if
#         email_type_list = ['@gmail.com','@163.com','@126.com','@sina.com','@yahoo.com.cn','@yahoo.cn','@tom.com',
#                            '@hexun.com','@21cn.com','@sohu.com','@sogou.com','@qq.com','@56.com','@3126.com',
#                            '@china.com','@139.com','@yahoo.com','@live.cn','@hotmail.com','@foxmail.com',
#                            '@vip.sina.cn','@msn.com','@msn.cn','@263.net.cn','@263.net','@yeah.net',
#                            '@yeah.com','@5ydns.com','@35.com','@zzy.cn','@net.cn','@xinnet.com']
#         temp = getTopDomain(ob['domain'])
#         if temp != False:
#             email_type_list.append("@%s" % (temp))
#         #end if
#
#         output = []
#
#         res, content = http.request(url, 'GET', headers=header)
#         if res and res.has_key('status') and res['status'] == '200':
#             content_list = content.replace("\r\n","\n").split("\n")
#             for item in content_list:
#                 for email in email_type_list:
#                     email1 = email
#                     email2 = email.replace("@","#")
#                     if item.find(email1) > 0 or item.find(email2) > 0:
#                         output.append(item)
#                     #end if
#                 #end for
#             #end for
#         #end if
#
#         if (output and len(output) > 0) or re.search(r"[a-zA-Z0-9_-]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+",content,re.I):
#             request = getRequest(url, domain=ob['domain'])
#             response = getResponse(res)
#             detail = "检测到邮件信息，可能导致信息泄露。"
#             result.append(getRecord(ob,url,ob['level'],detail,request,response,"\n".join(output)))
#         #end if
#
#         return result
#
#     except Exception,e:
#         logger.error("File:EmailDiscloseScript.py, run_url function :%s" % (str(e)))
#         return []
#     #end try
# #end def
#
