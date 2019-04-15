# -*- coding: utf-8 -*-
from random import randint
from engine.engine_utils.params import query2dict, dict2query, db_params2dict
from copy import deepcopy
from engine.engine_utils.common import *
from engine.logger import scanLogger as logger
# from engine.engine_utils.rule_result_judge import page_similar
reload(sys)
sys.setdefaultencoding('utf-8')


# def check_page_similar(status1, content1, status2, content2, rate=0.8):
#     '''
#     用于比较页面相似度，插件规则都可以用
#     :param status: 响应状态码  str
#     :param content: 响应body  str
#     :param rate:  相似度阈值
#     :return:  True 大于等于阈值，表示页面相似度高； False 小于阈值，表示页面相似度不高
#     '''
#     page_dict = {'status': status2, 'content': content2, 'similar_rate': rate}
#     return page_similar(status1, content1, page_dict)


def run_url(http, ob, item):
    method = item.get('method')
    method = method.lower()
    if method not in ['get', 'post']:
        return []
    params = item.get('params')

    inj_list = [
        # '''<sCrIpt>alert(123)</ScRiPt>''',
        # ''''><sCrIpt>alert(123)</ScRiPt>''',
        # '''"><sCrIpt>alert(123)</ScRiPt>''',
        # '''';</ScrIpt><sCrIpt>alert(123)</ScRiPt>//''',
        # '''";</ScrIpt><sCrIpt>alert(123)</ScRiPt>//''',
        '''-->''''''"""""">>>>>>;;;;;;</ScrIpt><sCrIpt>alert(123)</ScRiPt>//''',
        '''-->''''''"""""">>>>>>;;;;;;<source%20onerror="javascript:alert(123)">''',
        '''-->''''''"""""">>>>>>;;;;;;<img src=1 onerror=alert(1)>'''
    ]

    url = item['url']
    scheme = ob['scheme']
    domain = ob['domain']
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    if source_ip:
        domain = source_ip
    url_path = urlparse.urlparse(url).path
    result = []

    re_obj = re.compile('(<script>alert\(123\)</script>|javascript:alert\(123\)">|onerror=alert\(1\)>)')
    detail = "检测到XSS漏洞"

    try:
        # get 方法
        if method == 'get':
            # 没有参数，就直接路径注入
            if not params:
                for payload in inj_list:
                    if not url_path or url_path[-1] != '/':
                        payload = '/' + payload
                    new_url = '%s://%s%s%s' % (scheme, domain, url_path, payload)
                    res, content = http.request(url=new_url, method='GET', headers=header)
                    if re_obj.search(content, re.I):
                        request = getRequest(new_url, domain=ob['domain'])
                        response = getResponse(res, content)
                        result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
            # 有参数就参数注入，query注入
            else:
                query_dict = query2dict(params)
                for payload in inj_list:
                    for k, v in query_dict.iteritems():
                        query_dict_cp = deepcopy(query_dict)
                        if v:
                            query_dict_cp[k] = str(v) + payload
                        else:
                            query_dict_cp[k] = '1' + payload
                        new_query = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                        new_url = '%s://%s%s?%s' % (scheme, domain, url_path, new_query)
                        res, content = http.request(url=new_url, method='GET', headers=header)
                        # if res.get('status') and res.get('status') == '200':
                        if re_obj.search(content, re.I):
                            request = getRequest(new_url, domain=ob['domain'])
                            response = getResponse(res, content)
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
        # post 方法
        else:
            query = urlparse.urlparse(url).query
            body = item.get('params')
            # query 部分注入，body不变
            if query:
                body_str = None
                if body:
                    body_dict = db_params2dict(body)
                    body_str = dict2query(params_dict=body_dict, isUrlEncode=False)
                query_dict = query2dict(query)
                for payload in inj_list:
                    for k, v in query_dict.iteritems():
                        query_dict_cp = deepcopy(query_dict)
                        if v:
                            query_dict_cp[k] = str(v) + payload
                        else:
                            query_dict_cp[k] = '1' + payload
                        new_query = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                        new_url = '%s://%s%s?%s' % (scheme, domain, url_path, new_query)
                        res, content = http.request(url=new_url, method='POST', headers=header, body=body_str)
                        # if res.get('status') and res.get('status') == '200':
                        if re_obj.search(content, re.I):
                            request = postRequest(new_url, domain=ob['domain'])
                            response = getResponse(res, content)
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
            # body部分注入，query不变
            if body:
                params_dict = db_params2dict(body)
                for payload in inj_list:
                    for k, v in params_dict.iteritems():
                        params_dict_cp = deepcopy(params_dict)
                        if v:
                            params_dict_cp[k] = str(v) + payload
                        else:
                            params_dict_cp[k] = '1' + payload
                        new_params = dict2query(params_dict=params_dict_cp, isUrlEncode=False)
                        new_url = '%s://%s%s?%s' % (scheme, domain, url_path, query)
                        res, content = http.request(url=new_url, method='POST', headers=header, body=new_params)
                        # if res.get('status') and res.get('status') == '200':
                        if re_obj.search(content, re.I):
                            request = postRequest(new_url, domain=ob['domain'])
                            response = getResponse(res, content)
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:xss_inject_new.py, run_url function get method:%s" % (str(e)))
    return result