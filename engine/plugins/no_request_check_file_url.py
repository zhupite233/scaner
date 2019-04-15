#!/usr/bin/python
# -*- coding: utf-8 -*-
import json

from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http, ob, item):

    try:
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern1 = r'.+(upload).*'
        pattern2 = r'("type":\s*"file")'
        result = []
        if re.search(pattern1, path, re.I) or re.search(pattern2, json.dumps(params), re.I):
            res = {'status': '200','content-location': path, 'pragma': 'no-cache', 'cache-control':
                    'no-cache, must-revalidate', "content-type": 'text/html;charset=utf-8'}
            response = getResponse(res)
            request = getRequest(path, domain=ob['domain'])

            detail = "在站点上检测到潜在的文件上传风险点"
            result.append(getRecord(ob, path, ob['level'], detail, request, response))

        return result

    except Exception,e:
        logger.error("File:DirectoryTraversal.py, run_url function :%s" % (str(e)))
        return []




