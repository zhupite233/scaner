# --*--coding: utf-8 --*--
import json
from urlparse import urlparse, urlunparse

from engine.engine_utils.inj_functions import query_inject, body_inject, header_inject
from engine.engine_utils.params import post_params2str
from engine.engine_utils.rule_result_judge import result_judge
from engine.engine_utils.common import getRequest, getResponse, getRecord
from engine.logger import scanLogger as logger
import MySQLdb
import MySQLdb.cursors
from engine.engineConfig import *
from engine.engine_utils.rule_result_judge import page_similar
from engine.engine_lib.HttpRequest import HttpRequest


def run_url(http, ob, item):
    result_list = []
    url = item['url']
    params = item['params']
    method = item['method']

    task_id = ob['taskId']
    # rules = [{"judge": {"similar": {"mode": "less_than", "value": 0.6}, "http_code": {"mode": "equal", "value": ["200", "999"]}},
    #           "inj_way": "replace", "inj_point": "", "inj_value": "../../../../../../../../../../../../../etc/passwd", "area": "params"},]

    # 从数据库读取task的规则列表（取除path之外的规则）
    rules = get_rules(task_id)
    # rule example:
    ''' {
            'area':'params',  # inj_types: headers, path, params(body/query)
            'inj_point':'(path|page|download)',
            'inj_value':['../../../../../etc/passwd'],
            'inj_way':'replace',
            'judge':{'http_code':'200','keyword':'(root|bin|nobody):'}
        }
    '''
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
    # http = Http(timeout=ob['webTimeout'])
    if len(rules) == 0:
        pass
    else:
        url_parse = urlparse(url)
        scheme = url_parse.scheme
        domain = url_parse.netloc
        path = url_parse.path
        query = url_parse.query
        source_ip = ob.get('source_ip')
        if source_ip:
            domain = source_ip
        if query:
            url = "%s://%s%s?%s" % (scheme, domain, path, query)
        else:
            url = "%s://%s%s" % (scheme, domain, path)
        for rule in rules:

            res_method = 'HEAD' if rule.get('if_head') else method.upper()
            if rule.get('judge').get('keyword') or rule.get('judge').get('content') or rule.get('judge').get('similar'):
                redirects = 5
            else:
                http = HttpRequest({'timeout': 10, 'follow_redirects':False})
                redirects = 0
                res_method = 'HEAD'
            # header injection
            if 'header' == rule.get('area'):

                new_header_list = header_inject(header, rule.get('inj_point'), rule.get('inj_value'), rule.get('inj_way'))
                for new_header in new_header_list:
                    if 'post' == method:
                        params = post_params2str(params)
                    try:
                        res, content = http.request(url, res_method, params, new_header, redirections=redirects)
                        # # ---------- verify 404 page by lichao
                        if page_similar(res.get('status'), content, ob.get('404_page')):
                            continue
                        # # ----------- verify waf page by lichao
                        if page_similar(res.get('status'), content, ob.get('waf_page')):
                            continue
                        # # -----------
                        # # get normal_res first if content compare is necessary
                        if rule.get('judge').get('similar'):
                            normal_res, normal_cont = http.request(url, res_method, params, header)
                        else:
                            normal_res = None
                            normal_cont = None

                        # 根据http请求结果判断是否有漏洞
                        if result_judge(normal_res, normal_cont, res, content, **rule.get('judge')):
                            response = getResponse(res, content)
                            request = getRequest(url, res_method, headers=new_header, body=params, domain=ob['domain'])
                            detail = "注入规则：" + json.dumps(rule)
                            ob['vulId'] = rule.get('vul_id')
                            result_list.append(getRecord(ob, url, ob['level'], detail, request, response))
                    except Exception,e:
                        logger.exception("File:rule_scan_script_url.py,rule_id:%s , run_domain function :%s" % (rule.get('rule_id'), str(e)))
                        pass

            # params  injection include query&body
            elif 'params' == rule.get('area'):
                try:
                    if url_parse.query:
                        new_query_list = query_inject(url_parse.query, rule.get('inj_point'), rule.get('inj_value'), rule.get('inj_way'))
                        for query in new_query_list:
                            new_url = urlunparse((url_parse.scheme, domain, url_parse.path, '', query, ''))
                            if 'post' == method:
                                new_params = post_params2str(params)
                            try:
                                res, content = http.request(new_url, res_method, body=new_params, headers=header)
                                # print res
                                # # ---------- verify 404 by lichao
                                if page_similar(res.get('status'), content, ob.get('404_page')):
                                    continue
                                # # ----------- verify waf page by lichao
                                if page_similar(res.get('status'), content, ob.get('waf_page')):
                                    continue

                                # # get normal_res first if content compare is necessary
                                if rule.get('judge').get('similar'):
                                    normal_res, normal_cont = http.request(url, res_method, params, header)
                                else:
                                    normal_res = None
                                    normal_cont = None
                                # 根据http请求结果判断是否有漏洞
                                if result_judge(normal_res, normal_cont, res, content, **rule.get('judge')):
                                    response = getResponse(res, content)
                                    request = getRequest(new_url, res_method, headers=header, body=params, domain=ob['domain'])
                                    detail = "注入规则：" + json.dumps(rule)
                                    ob['vulId'] = rule.get('vul_id')
                                    result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                            except Exception,e:
                                logger.exception("File:rule_scan_script_url.py,rule_id:%s , run_domain function :%s" % (rule.get('rule_id'), str(e)))
                                pass
                    if params:
                        if 'get' == method:
                            new_query_list = query_inject(params, rule.get('inj_point'), rule.get('inj_value'), rule.get('inj_way'))
                            for query in new_query_list:
                                new_url = url+"?"+query
                                try:
                                    res, content = http.request(new_url, res_method, body=None, headers=header)
                                    # print res
                                    # # ---------- verify 404 by lichao
                                    if page_similar(res.get('status'), content, ob.get('404_page')):
                                        continue
                                    # # ----------- verify waf page by lichao
                                    if page_similar(res.get('status'), content, ob.get('waf_page')):
                                        continue
                                    # # get normal_res first if content compare is necessary
                                    if rule.get('judge').get('similar'):
                                        normal_res, normal_cont = http.request(url, res_method, body=None, headers=header)
                                    else:
                                        normal_res = None
                                        normal_cont = None
                                    # 根据http请求结果判断是否有漏洞
                                    if result_judge(normal_res, normal_cont, res, content, **rule.get('judge')):
                                        response = getResponse(res, content)
                                        request = getRequest(new_url, res_method, headers=header, body=params, domain=ob['domain'])
                                        detail = "注入规则：" + json.dumps(rule)
                                        ob['vulId'] = rule.get('vul_id')
                                        result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                                except Exception,e:
                                    logger.exception("File:rule_scan_script_domain.py,rule_id:%s , run_domain function :%s" % (rule.get('rule_id'), str(e)))
                                    pass
                        else:
                            body_dict = json.loads(params)
                            new_body_list = body_inject(body_dict, rule.get('inj_point'), rule.get('inj_value'), rule.get('inj_way'))
                            if new_body_list:
                                for body in new_body_list:
                                    # new_url = urlunparse(url.scheme, url.netloc, url.path, params='',
                                    #                      query=url.query, fragment='')
                                    try:
                                        res, content = http.request(url, res_method, body=body, headers=header, redirections=redirects)
                                        # # ---------- verify 404 by lichao
                                        if page_similar(res.get('status'), content, ob.get('404_page')):
                                            continue
                                        # # ----------- verify waf page by lichao
                                        if page_similar(res.get('status'), content, ob.get('waf_page')):
                                            continue
                                        # # get normal_res first if content compare is necessary
                                        if rule.get('judge').get('similar'):
                                            if 'post' == method:
                                                new_params = post_params2str(params)
                                            normal_res, normal_cont = http.request(url, res_method, new_params, header)
                                        else:
                                            normal_res = None
                                            normal_cont = None
                                        # 根据http请求结果判断是否有漏洞
                                        if result_judge(normal_res, normal_cont, res, content, **rule.get('judge')):
                                            response = getResponse(res, content)
                                            request = getRequest(url, res_method, headers=header, body=params, domain=ob['domain'])
                                            detail = "注入规则：" + json.dumps(rule)
                                            ob['vulId'] = rule.get('vul_id')
                                            result_list.append(getRecord(ob, url, ob['level'], detail, request, response))
                                    except Exception,e:
                                        logger.exception("File:rule_scan_script_domain.py,rule_id:%s , run_domain function :%s" % (rule.get('rule_id'), str(e)))
                                        pass
                    # elif 'url' == rule.get('area'):
                    #     new_url = url_inject(url, rule.get('inj_value'), rule.get('inj_way'))
                    #     res, content = http.request(new_url, 'GET')
                    #     if rule.get('judge').get('content'):
                    #         normal_res, normal_cont = http.request(url, 'GET')
                    #     else:
                    #         normal_res = None
                    #         # 根据http请求结果判断是否有漏洞
                    #     if result_judge(normal_res, res, content, **rule.get('judge')):
                    #         response = getResponse(res)
                    #         request = getRequest(url)
                    #         detail = "注入规则：" + json.dumps(rule)
                    #         result_list.append(getRecord(ob, url, ob['level'], detail, request, response))
                    else:
                        pass
                except Exception,e:
                    # print e
                    logger.exception("File:rule_scan_script_url.py,rule_id:%s , run_url function :%s" % (rule.get('rule_id'), str(e)))
    print result_list
    return result_list


def get_rules(task_id):
    sql = "select web_scan_rule.rule_json, web_scan_rule.if_head, web_scan_rule.vul_id, web_scan_rule.rule_id " \
          "from web_scan_rule, task_rule_family_ref " \
          "where web_scan_rule.rule_family=task_rule_family_ref.rule_family_id and task_rule_family_ref.task_id=%s" \
          " and web_scan_rule.run_mode='%s'" % (task_id, 'url')
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass=MySQLdb.cursors.DictCursor)
    cursor = db.cursor()
    cursor.execute(sql)
    rule_list = cursor.fetchall()
    rules = []
    for rule_json in rule_list:
        rule_json_str = rule_json.get('rule_json')
        if rule_json_str:
            rule_dict = json.loads(rule_json_str)
            rule_dict['if_head'] = rule_json.get('if_head')
            rule_dict['vul_id'] = rule_json.get('vul_id')
            rule_dict['rule_id'] = rule_json.get('rule_id')
            rules.append(rule_dict)
    return rules