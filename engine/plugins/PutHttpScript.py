#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger

def run_url(http,ob,item):
    try:

        result = []
        # 与插件 DangerHttpMethodScript 功能重复
        # if item['method'] != 'get':
        #     return []
        # if item['params'] != '':
        #     return []
        # if item['url'][-1] != "/":
        #     return []
        # url = item['url']
        # res, content = http.request(url,"OPTIONS")
        # if res and res.has_key('status') and res['status'] in ['200','403'] and ((res.has_key('allow') and res['allow'].lower().find("put") >= 0) or (res.has_key('public') and res['public'].lower().find('put') >= 0)):
        #     detail = "该目录支持PUT请求，可能导致网站被上传木马，导致网站被破坏和泄露。"
        #     request = getRequest(url,"OPTIONS")
        #     response = getResponse(res)
        #
        #     put_url = "%stest.txt" % (url)
        #     res, content = http.request(put_url)
        #     if res and res.has_key('status') and res['status'] == '200' and content.find('test') >= 0:
        #         output = "请求URL：%s 将返回字符串：test" % (put_url)
        #         result.append(getRecord(ob,url,ob['level'],detail,request,response,output))

        return result
        
    except Exception,e:
        logger.error("File:PutHttpScript.py, run_url function :%s" % (str(e)))
        return []
    #end try    
#end def



