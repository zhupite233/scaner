# --*-- coding: utf-8 --*--
import json
from flask import jsonify, request
from flask_login import login_required
from web.utils.decorater import permission_required
from web.utils.logger import mylogger as logger
from web import web, db
from web.models.rule import Rule, RuleFamily
from web.models.web_policy_db import WebVulFamily, WebVulList, WebVulListCopy, WebVulFamilyRef
from web.api_1_0.web_policy_api import add_policy_script
from markupsafe import escape

@web.route('/rules', methods=['POST'])
@web.route('/rules/<int:rule_id>', methods=['PUT'])
# @permission_required('')
@login_required
def create_rule(rule_id=None):
    rule_name = request.values.get('rule_name')
    rule_family = request.values.get('rule_family')
    # rule_tag = request.values.get('rule_tag')
    rule_tag = ''  # tag标签在scan_site.py写入字典scan_cnf里面，此处停用。为不影响其他代码，暂时置空处理。
    level = request.values.get('bug_level')
    if_head = True if request.values.get('if_head') else False
    run_mode = request.values.get('run_mode')
    inj_area = request.values.get('inj_area')
    inj_way = request.values.get('inj_way')
    inj_point = request.values.get('inj_point')
    inj_value_str = request.values.get('inj_value')
    code_mode = request.values.get('code_mode')
    judge_code1 = request.values.get('judge_code1')
    judge_code2 = request.values.get('judge_code2')
    judge_keyword = request.values.get('judge_keyword')
    content_mode = request.values.get('content_mode')
    judge_content = request.values.get('judge_content')
    similar_mode = request.values.get('similar_mode')
    similar = request.values.get('similar')
    describe = request.values.get('describe')
    solution = request.values.get('solution')
    judge_str = request.values.get('judge')

    # 规范传入参数，防止XSS
    rule_name = escape(rule_name.decode('utf-8'))
    describe = escape(describe.decode('utf-8'))
    solution = escape(solution.decode('utf-8'))
    judge = {}
    if code_mode:
        code_dict = {'mode': code_mode}
        code_value = []
        if judge_code1:
            code_value.append(judge_code1)
        else:
            code_value.append('0')
        if judge_code2:
            code_value.append(judge_code2)
        else:
            code_value.append('999')
        code_dict['value'] = code_value
        judge["http_code"] = code_dict
    if judge_keyword:
        judge["keyword"] = judge_keyword
    if content_mode:
        content_dict = {'mode': content_mode, 'value': judge_content}
        judge["content"] = content_dict
    if similar_mode:
        similar_dict = {'mode': similar_mode, 'value': float(similar)/100}
        judge["similar"] = similar_dict

    if 'POST' == request.method:
        try:
            inj_values = inj_value_str.split('\r\n')
            if '' in inj_values:
                inj_values.remove('')
            # vul_id = rule_name.split('-')[0]
            # rule_exists = db.session.query(Rule).filter(Rule.vul_id == vul_id).first()
            # if rule_exists:
            #     return jsonify(dict(status=False, desc='ID为'+vul_id+'的漏洞已经存在'))
            family = db.session.query(WebVulFamily).filter(WebVulFamily.desc == rule_family).first()
            module = db.session.query(WebVulFamily).filter(WebVulFamily.id == family.parent_id).first()
            vul_script = WebVulList(0, rule_name, 1, family.desc, module.desc, 3, None, level,
                                describe, solution, None, 750, rule_tag, family.id, module.id)
            db.session.add(vul_script)
            db.session.flush()
            vul_id = vul_script.id
            vul_script.vul_id = vul_id
            db.session.add(vul_script)
            db.session.commit()
            ref = WebVulFamilyRef(family.parent_id, family.id, vul_id)
            db.session.add(ref)
            db.session.commit()
            # for inj_value in inj_values:
            rule_json = {"area": inj_area, "inj_way": inj_way, "inj_point": inj_point, "inj_value": inj_values, "judge": judge}
            rule = Rule(family.id, rule_name, json.dumps(rule_json), inj_area, inj_way, inj_point, json.dumps(inj_values),
                        json.dumps(judge), describe, run_mode, rule_tag, if_head, vul_id)
            db.session.add(rule)
            db.session.commit()
            # 规则从web_vul_list_copy 导入 web_vul_list ，并删除copy中的记录
            # web_vul_copy = db.session.query(WebVulListCopy).filter(WebVulListCopy.vul_id == vul_id).first()
            # result = add_policy_script(web_vul_copy.vul_name, 3, '', web_vul_copy.level, web_vul_copy.desc,
            #                            web_vul_copy.solu, web_vul_copy.priority, family.id, vul_id=vul_id, tag=rule_tag)
            # if not result:
            #     raise Exception
            # db.session.query(WebVulListCopy).filter(WebVulListCopy.vul_id == vul_id).delete()
            # db.session.commit()
        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功'))
    else:

        try:
            value_list = json.loads(inj_value_str)
            rule_json = {"area": inj_area, "inj_way": inj_way, "inj_point": inj_point, "inj_value": value_list,
                         "judge": json.loads(judge_str)}
            rule = db.session.query(Rule).filter(Rule.rule_id == rule_id).first()
            rule.rule_name = rule_name
            rule.rule_family = rule_family
            rule.rule_json = json.dumps(rule_json)
            rule.area = inj_area
            rule.inj_way = inj_way
            rule.inj_point = inj_point
            rule.inj_value = inj_value_str
            rule.judge = judge_str
            rule.describe = describe
            rule.run_mode = run_mode
            rule.if_head = if_head
            db.session.add(rule)
            db.session.commit()
        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/rules/<int:rule_id>', methods=['DELETE'])
# @permission_required('')
@login_required
def delete_rule(rule_id):
    try:
        db.session.query(Rule).filter(Rule.rule_id == rule_id).delete()
        db.session.commit()
    except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='删除失败'))
    else:
        return jsonify(dict(status=True, desc='删除成功'))


@web.route('/rule_family', methods=['POST'])
@web.route('/rule_family/<int:rule_family_id>', methods=['PUT'])
# @permission_required('')
@login_required
def create_rule_family(rule_family_id=None):
    name = request.values.get('name')
    describe = request.values.get('describe')
    priority = request.values.get('priority')

    if 'POST' == request.method:
        try:
            family = RuleFamily(name, describe, priority)
            db.session.add(family)
            db.session.commit()
        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='添加失败'))
        else:
            return jsonify(dict(status=True, desc='添加成功'))
    else:
        try:

            family = db.session.query(RuleFamily).filter(RuleFamily.id == rule_family_id).first()
            family.name = name
            family.describe = describe
            family.priority = priority
            db.session.add(family)
            db.session.commit()
        except Exception as e:
            logger.exception(e)
            return jsonify(dict(status=False, desc='更新失败'))
        else:
            return jsonify(dict(status=True, desc='更新成功'))


@web.route('/rule_family/<int:rule_family_id>', methods=['DELETE'])
# @permission_required('')
@login_required
def delete_rule_family(rule_family_id):
    try:
        db.session.query(RuleFamily).filter(RuleFamily.id == rule_family_id).delete()
        db.session.commit()
    except Exception as e:
            logger.exception(e)

            return jsonify(dict(status=False, desc='删除失败'))
    else:
        return jsonify(dict(status=True, desc='删除成功'))