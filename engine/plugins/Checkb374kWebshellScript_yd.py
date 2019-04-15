#!/usr/bin/python
# -*- coding: utf-8 -*-
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger


def run_url(http,ob,item):
    result = []
    try:
        frame = ob.get('siteType')
        if frame and frame in ['asp', 'aspx', 'jsp']:
            return []

        url = item['url']
        if re.search('b374k', url, re.I):
            detail = "检测到b374k木马"
            request = getRequest(url, domain=ob['domain'])
            result.append(getRecord(ob, url, ob['level'], detail, request, response=''))

    except Exception, e:
        logger.error("File:Checkb374kWebshellScript_yd.py, run_domain function :%s" % (str(e)))

    return result



