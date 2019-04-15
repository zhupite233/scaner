# -*- coding: utf-8 -*-
from random import randint
from engine.engine_utils.params import query2dict, dict2query, db_params2dict
from copy import deepcopy
from engine.engine_utils.rule_result_judge import page_similar
from engine.engine_utils.common import *
from engine.plugins.sql_inject_new_error import check_db_error
from engine.logger import scanLogger as logger

reload(sys)
sys.setdefaultencoding('utf-8')


def num_type():
    '''
    纯数字类型
    :return:
    '''
    random_num1 = randint(0, 499)
    random_num2 = randint(500, 999)
    true_load = " oR {0}={1}".format(random_num1, random_num1)
    false_load = " aNd {0}={1}".format(random_num1, random_num2)
    return [true_load, false_load]


def sql_error_type():
    '''
    ERROR型SQL注入
    :return:
    '''
    true_load = "\""
    false_load = "\'"
    return [true_load, false_load]


def single_quote():
    '''
    单引号型
    :return:
    '''
    random_num1 = randint(0, 499)
    random_num2 = randint(500, 999)
    true_load = "'oR'%d'='%d" % (random_num1, random_num1)
    false_load = "'aND'%d'='%d" % (random_num1, random_num2)
    return [true_load, false_load]


def double_quotes():
    '''
    双引号型
    :return:
    '''
    random_num1 = randint(0, 499)
    random_num2 = randint(500, 999)
    true_load = '"oR"%d"="%d' % (random_num1, random_num1)
    false_load = '"ANd"%d"="%d' % (random_num1, random_num2)
    return [true_load, false_load]


def like_type():
    '''
    百分号型，like语句，搜索
    :return:
    '''
    random_num1 = randint(0, 499)
    random_num2 = randint(500, 999)
    true_load = "%%'oR'%d'='%d'oR'%%'='" % (random_num1, random_num1)
    false_load = "%%'aNd'%d'='%d'aNd'%%'='" % (random_num1, random_num2)
    return [true_load, false_load]


def check_page_similar(status1, content1, status2, content2, rate=0.96):
    '''
    用于比较页面相似度，插件规则都可以用
    :param status: 响应状态码  str
    :param content: 响应body  str
    :param rate:  相似度阈值
    :return:  True 大于等于阈值，表示页面相似度高； False 小于阈值，表示页面相似度不高
    '''
    page_dict = {'status': status2, 'content': content2, 'similar_rate': rate}
    return page_similar(status1, content1, page_dict)


def run_inj(http, ob, item, payloads, inj_type=None):
    method = item.get('method')
    if not method:
        return []
    method = method.lower()
    if method not in ['get', 'post']:
        return []
    params = item.get('params')
    if not params:
        return []

    url = item['url']
    scheme = ob['scheme']
    domain = ob['domain']
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    if source_ip:
        domain = source_ip
    url_path = urlparse.urlparse(url).path
    result = []

    try:
        # get 方法
        if method.lower() == 'get':
            query_dict = query2dict(params)
            for k, v in query_dict.iteritems():
                query_dict_cp = deepcopy(query_dict)
                payload_t, payload_f = payloads
                if v:
                    query_dict_cp[k] = v + payload_t
                else:
                    query_dict_cp[k] = '1' + payload_t
                query_t = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                if v:
                    query_dict_cp[k] = v + payload_f
                else:
                    query_dict_cp[k] = '1' + payload_f
                query_f = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                url_t = '%s://%s%s?%s' % (scheme, domain, url_path, query_t)
                url_f = '%s://%s%s?%s' % (scheme, domain, url_path, query_f)
                res_t, content_t = http.request(url=url_t, method='GET', headers=header)
                res_f, content_f = http.request(url=url_f, method='GET', headers=header)
                status_t = res_t.get('status', '0')
                status_f = res_f.get('status', '0')
                if "ERROR型" == inj_type:
                    res_d, db_type_d, msg_d = check_db_error(content_t)
                    # if res_d or (status_t == '500' and not page_similar(res_t.get('status'), content_t, ob.get('waf_page'))):
                    if res_d:
                        detail = "检测到 %s sql注入漏洞" % inj_type
                        request = getRequest(url_t, domain=ob['domain'])
                        response = getResponse(res_t, content_t)
                        # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                        # status_t, status_f, content_t, content_f))
                        result.append(getRecord(ob, url_t, ob['level'], detail, request, response))
                    else:
                        res_s, db_type_s, msg_s = check_db_error(content_f)
                        # if res_s or (status_f == '500' and not page_similar(res_f.get('status'), content_f, ob.get('waf_page'))):
                        if res_s:
                            detail = "检测到 %s sql注入漏洞" % inj_type
                            request = getRequest(url_f, domain=ob['domain'])
                            response = getResponse(res_f, content_f)
                            # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                            # status_t, status_f, content_t, content_f))
                            result.append(getRecord(ob, url_f, ob['level'], detail, request, response))
                else:
                    similar = check_page_similar(status1=status_t, content1=content_t, status2=status_f, content2=content_f)
                    similar_waf = page_similar(status_t, content_t, ob.get('waf_page'))
                    if not similar and not similar_waf:
                        detail = "检测到 %s sql注入漏洞" % inj_type
                        logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (status_t, status_f, content_t, content_f))
                        request = getRequest(url_f, domain=ob['domain'])
                        response = getResponse(res_f, content_f)
                        # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                        # status_t, status_f, content_t, content_f))
                        result.append(getRecord(ob, url_f, ob['level'], detail, request, response))
        # post 方法
        else:
            query = urlparse.urlparse(url).query
            body = item.get('params')
            # query 部分注入，body不变
            if query:
                body_str = ''
                if body:
                    body_dict = db_params2dict(body)
                    body_str = dict2query(params_dict=body_dict, isUrlEncode=True)
                query_dict = query2dict(query)
                for k, v in query_dict.iteritems():
                    query_dict_cp = deepcopy(query_dict)
                    payload_t, payload_f = payloads
                    if v:
                        query_dict_cp[k] = v + payload_t
                    else:
                        query_dict_cp[k] = '1' + payload_t
                    query_t = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                    if v:
                        query_dict_cp[k] = v + payload_f
                    else:
                        query_dict_cp[k] = '1' + payload_f
                    query_f = dict2query(params_dict=query_dict_cp, isUrlEncode=True)
                    url_t = '%s://%s%s?%s' % (scheme, domain, url_path, query_t)
                    url_f = '%s://%s%s?%s' % (scheme, domain, url_path, query_f)
                    res_t, content_t = http.request(url=url_t, method='POST', headers=header, body=body_str)
                    res_f, content_f = http.request(url=url_f, method='POST', headers=header, body=body_str)
                    status_t = res_t.get('status', '0')
                    status_f = res_f.get('status', '0')
                    if "ERROR型" == inj_type:
                        res_d, db_type_d, msg_d = check_db_error(content_t)
                        # if res_d or (status_t == '500' and not page_similar(res_t.get('status'), content_t, ob.get('waf_page'))):
                        if res_d:
                            detail = "检测到 %s sql注入漏洞" % inj_type
                            request = postRequest(url_t, body=body_str, domain=ob['domain'])
                            response = getResponse(res_t, content_t)
                            # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                            # status_t, status_f, content_t, content_f))
                            result.append(getRecord(ob, url_t, ob['level'], detail, request, response))
                        else:
                            res_s, db_type_s, msg_s = check_db_error(content_f)
                            # if res_s or (status_f == '500' and not page_similar(res_f.get('status'), content_f, ob.get('waf_page'))):
                            if res_s:
                                detail = "检测到 %s sql注入漏洞" % inj_type
                                request = postRequest(url_t, body=body_str, domain=ob['domain'])
                                response = getResponse(res_f, content_f)
                                # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                                # status_t, status_f, content_t, content_f))
                                result.append(getRecord(ob, url_f, ob['level'], detail, request, response))
                    else:
                        similar = check_page_similar(status1=status_t, content1=content_t, status2=status_f,
                                                     content2=content_f)
                        similar_waf = page_similar(status_t, content_t, ob.get('waf_page'))
                        if not similar and similar_waf:
                            detail = "检测到 %s sql注入漏洞" % inj_type
                            request = postRequest(url_t, body=body_str, domain=ob['domain'])
                            response = getResponse(res_f, content_f)
                            # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                            # status_t, status_f, content_t, content_f))
                            result.append(getRecord(ob, url_f, ob['level'], detail, request, response))
            # body部分注入，query不变
            if body:
                params_dict = db_params2dict(body)
                for k, v in params_dict.iteritems():
                    params_dict_cp = deepcopy(params_dict)
                    payload_t, payload_f = payloads
                    if v:
                        params_dict_cp[k] = v + payload_t
                    else:
                        params_dict_cp[k] = '1' + payload_t
                    params_t = dict2query(params_dict=params_dict_cp, isUrlEncode=True)
                    if v:
                        params_dict_cp[k] = v + payload_f
                    else:
                        params_dict_cp[k] = '1' + payload_f
                    params_f = dict2query(params_dict=params_dict_cp, isUrlEncode=True)
                    new_url = '%s://%s%s?%s' % (scheme, domain, url_path, query)
                    res_t, content_t = http.request(url=new_url, method='POST', headers=header, body=params_t)
                    res_f, content_f = http.request(url=new_url, method='POST', headers=header, body=params_f)
                    status_t = res_t.get('status', '0')
                    status_f = res_f.get('status', '0')
                    if "ERROR型" == inj_type :
                        res_d, db_type_d, msg_d = check_db_error(content_t)
                        # if res_d or (status_t == '500' and not page_similar(res_t.get('status'), content_t, ob.get('waf_page'))):
                        if res_d:
                            detail = "检测到 %s sql注入漏洞" % inj_type
                            request = postRequest(new_url, body=params_t, domain=ob['domain'])
                            response = getResponse(res_t, content_t)
                            # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                            # status_t, status_f, content_t, content_f))
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                        else:
                            res_s, db_type_s, msg_s = check_db_error(content_f)
                            # if res_s or (status_f == '500' and not page_similar(res_f.get('status'), content_f, ob.get('waf_page'))):
                            if res_s:
                                detail = "检测到 %s sql注入漏洞" % inj_type
                                request = postRequest(new_url, body=params_f, domain=ob['domain'])
                                response = getResponse(res_f, content_f)
                                # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                                # status_t, status_f, content_t, content_f))
                                result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
                    else:
                        similar = check_page_similar(status1=status_t, content1=content_t, status2=status_f,
                                                     content2=content_f)
                        similar_waf = page_similar(status_t, content_t, ob.get('waf_page'))
                        if not similar and similar_waf:
                            detail = "检测到 %s sql注入漏洞" % inj_type
                            request = postRequest(new_url, body=params_f, domain=ob['domain'])
                            response = getResponse(res_f, content_f)
                            # logger.error("status_t:%s, status_f:%s, content_t:%s, content_f:%s" % (
                            # status_t, status_f, content_t, content_f))
                            result.append(getRecord(ob, new_url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:sql_inject_new.py, run_url function:%s" % (str(e)))
    return result


def run_url(http, ob, item):
    result = []
    result_error = run_inj(http, ob, item, sql_error_type(), "ERROR型")
    payloads_list = [(num_type(), "数字型"), (single_quote(), "单引号型"), (double_quotes(), "双引号型"), (like_type(), "搜索型")]
    for payloads, inj_type in payloads_list:
        result = run_inj(http, ob, item, payloads, inj_type)
        if result:
            break
    if result_error:
        result.extend(result_error)
    return result
