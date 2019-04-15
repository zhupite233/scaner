# --*-- coding:utf-8 --*--
import re
import requests
from web import db
from web.models.web_policy_db import WebVulListCopy


def _add_rule_auto(rule_name, path, params ):
    data = dict(
        rule_name=rule_name,
        rule_family='系统命令执行',
        rule_tag=None,
        if_head=None,
        run_mode='domain',
        inj_area='path',
        inj_way='append',
        inj_point='',
        inj_value="%s?%s=https://scan.yundun.com/static/js/yundun_test.txt" % (path, params),
        code_mode='equal',
        judge_code1='200',
        judge_code2='',
        judge_keyword='(YunDun_ScANtEST)',
        content_mode='',
        judge_content='',
        similar_mode='',
        similar='',
        describe='',
        judge=None
    )
    add_rule_url = "http://115.238.237.32/rules"
    # resp = requests.get(add_task_url, data)
    resp = requests.post(add_rule_url, data)
    # print resp.json()['status']
    # print type(resp.json()['status'])
    if resp.json()['status']:

        return None
    else:
        return rule_name


def _run_add_rule():
    '''
    从WebVulListCopy取出现有规则，通过正则匹配获取注入值及参数
    临时开放规则创建接口（备用服务器上放行防火墙、取消权限控制，启动Web服务）
    脚本调用该接口发送http请求创建规则，并将规则从web_vul_list_copy 导入 web_vul_list ，
    删除copy中的记录
    注入值从WebVulListCopy中vul_name 获取

    :return:返回未成功创建部分规则列表
    '''
    rules = db.session.query(WebVulListCopy).filter(WebVulListCopy.level == 'HIGH', WebVulListCopy.scan_type == 3,
                                                WebVulListCopy.vul_name.like('%远程包含%')).all()
    error_list = []
    success_count = 0
    for rule in rules:
        temp = rule.vul_name.decode('utf8')
        pattern = re.compile(u"([^\u4e00-\u9fa5]+)")
        results = pattern.findall(temp)
        print results

        if len(results) >= 2:
            error = _add_rule_auto(str(rule.vul_id)+'-'+rule.vul_name, results[0], results[1])
            if error:
                error_list.append(error)
            else:
                success_count += 1
    print 'error_list:', error_list
    print 'success_count:', success_count

if __name__ == '__main__':

    _run_add_rule()