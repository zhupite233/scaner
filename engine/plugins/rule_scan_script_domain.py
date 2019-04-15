# --*-- coding: utf-8 --*--
import json
import MySQLdb
import MySQLdb.cursors

from engine.engine_utils.inj_functions import path_inject
from engine.engine_utils.rule_result_judge import result_judge

from engine.engine_utils.common import getRequest, getResponse, getRecord
from engine.engineConfig import *
from engine.logger import scanLogger as logger
from engine.engine_utils.rule_result_judge import page_similar
from engine.engine_lib.HttpRequest import HttpRequest


def run_domain(http, ob):
    scheme = ob['scheme']
    domain = ob['domain']
    header = {'Host': domain}
    source_ip = ob.get('source_ip')
    if source_ip:
        domain = source_ip
    path = ob['path']
    result_list = []

    task_id = ob['taskId']
    # 从数据库读取task的规则列表（取除path之外的规则）
    # rules = [{"judge": {"similar": {"mode": "less_than", "value": 0.6}, "http_code": {"mode": "equal", "value": ["200", "999"]}},
    #           "inj_way": "replace", "inj_point": "", "inj_value": "../../../../../../../../../../../../../../../etc/passwd", "area": "params"},]
    rules = get_rules(task_id)

    # rule example:
    ''' {
            'area':'query',  # 注入区域
            'inj_point':'(path|page|download)',  # 注入点
            'inj_value':'../../../../../etc/passwd',  # 注入值
            'inj_way':'replace',  # 注入方式
            'judge':{'http_code':'200','keyword':'(root|bin|nobody):'}  # 判断条件
        }
    '''
    if len(rules) == 0:
        pass
    else:
        timeout_count = 0
        for rule in rules:
            if timeout_count>80:
                break
            else:
                n = timeout_count/10 +1
                timeout = 10/n

            method = 'HEAD' if rule.get('if_head') else 'GET'
            if rule.get('judge').get('keyword') or rule.get('judge').get('content') or rule.get('judge').get('similar'):
                redirects = 5
                http = HttpRequest({'timeout': timeout, 'follow_redirects':True})
            else:
                http = HttpRequest({'timeout': timeout, 'follow_redirects':False})
                redirects = 0
                method = 'HEAD'

            # start path injection

            try:
                new_path_list = path_inject(path, rule.get('inj_value'), rule.get('inj_way'))
                for new_path in new_path_list:
                    url = "%s://%s%s" % (scheme, domain, path)
                    new_url = "%s://%s%s" % (scheme, domain, new_path)
                    # http = Http(timeout=ob['webTimeout'])
                    try:
                        import time
                        t1 = time.time()
                        res, content = http.request(new_url, method, redirections=redirects, headers=header)
                        # # ---------- verify 404 page by lichao
                        if page_similar(res.get('status'), content, ob.get('404_page')):
                            continue
                        # # ----------- verify waf page by lichao
                        if page_similar(res.get('status'), content, ob.get('waf_page')):
                            continue
                        # # -----------
                        if rule.get('judge').get('similar'):
                            normal_res, normal_cont = http.request(url, method, headers=header)
                        else:
                            normal_res = None
                            normal_cont = None
                        # 根据http请求结果判断是否有漏洞
                        judge = rule.get('judge')
                        if result_judge(normal_res, normal_cont, res, content, **judge):
                            response = getResponse(res, content)
                            request = getRequest(new_url, domain=ob['domain'])
                            detail = "注入规则：" + json.dumps(rule)
                            ob['vulId'] = rule.get('vul_id')
                            result_list.append(getRecord(ob, new_url, ob['level'], detail, request, response, ""))
                            # result.append(getRecord(ob,url,ob['level'],detail,request,response,output))
                    except Exception,e:
                        logger.exception("File:rule_scan_script_domain.py,rule_id:%s , run_domain function :%s" % (rule.get('rule_id'), str(e)))
                        timeout_count+=1
                        t2 = time.time()
                        print 'timeout_count:::::::', timeout_count, t2-t1
                        pass

            except Exception,e:
                # print e
                logger.exception("File:rule_scan_script_domain.py,rule_id:%s , run_domain function :%s" % (rule.get('rule_id'), str(e)))

    return result_list


def get_rules(task_id):
    sql = "select web_scan_rule.rule_json, web_scan_rule.if_head, web_scan_rule.vul_id, web_scan_rule.rule_id " \
          "from web_scan_rule, task_rule_family_ref, web_vul_list " \
          "where web_scan_rule.rule_family=task_rule_family_ref.rule_family_id and task_rule_family_ref.task_id=%s" \
          " and web_scan_rule.vul_id=web_vul_list.vul_id and web_vul_list.enable=1 and web_scan_rule.run_mode='%s'" % (task_id, 'domain')
    db = MySQLdb.connect(SCANER_DB_HOST, SCANER_DB_USER, SCANER_DB_PASSWORD, SCANER_DB_DATABASE, cursorclass = MySQLdb.cursors.DictCursor)
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

