#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json

from flask import render_template
from flask import request, jsonify
from flask_login import login_required
from web import web
from web.api_1_0.web_policy_api import *
from web.utils.parameter_check import verify_webpolicyid
from web.utils.decorater import permission_required
from markupsafe import escape


# 方案列表页面
# 容易被cc攻击，需要做缓存，或者限制查询频率
@web.route('/policy/list')
@login_required
@permission_required('read_policy')
def policy_list():
    web_policys = db.session.query(WebVulPolicy.id, WebVulPolicy.name).all()
    return render_template('policy.html', web_policys=web_policys)


# 创建方案,进入页面
@web.route('/policy/create')
@login_required
@permission_required('edit_policy')
def show_family_vul():
    family_dict, vul_dict = web_family_vul()
    return render_template('policy_create.html', family_dict=family_dict, \
                           family_json=json.dumps(family_dict), vul_json=json.dumps(vul_dict))


# 创建方案，提交
@web.route('/policy/create', methods=['POST'])
@login_required
@permission_required('edit_policy')
def policy_create():
    engine = request.values.get("engine")
    policy_name = request.values.get("policy_name")
    policy_name = escape(policy_name)
    # vul_dict = request.values.get("vul_dict")  #{family_id : [vul_id1, vul_id2]}
    vul_json = request.values.get("vul_json")
    # del vul_list[-1]

    if engine == "web":
        result = web_policy_create(policy_name, vul_json)
    elif engine == "host_scan":
        # host_policy_create(policy_name, vul_list)
        pass
    else:
        return jsonify(dict(status=False, desc='参数无效'))
        # print "参数无效"
    return result


# 删除方案
@web.route('/policy/delete', methods=['POST'])
@login_required
@permission_required('edit_policy')
def policy_delete():
    policy_id = request.values.get("policy_id")
    engine = request.values.get("engine")
    result = None
    if engine == "web":
        result = web_policy_delete(policy_id)
        return result
    elif engine == "host_scan":
        # host_policy_delete(policy_name)
        pass
    elif not engine:
        return jsonify(dict(status=False, desc='参数为空'))
    else:
        return jsonify(dict(status=False, desc='参数无效'))
    return result


# 策略修改页
@web.route('/policy/update', methods=['GET'])
@login_required
@permission_required('edit_policy')
def policy_info():
    policy_id = request.values.get("policy_id")
    if not policy_id:  # policy_id为空，返回提示信息
        return jsonify(dict(status=False, desc='策略id不能为空'))
    policy = verify_webpolicyid(policy_id)
    if not policy:  # policy_id在数据库里不存在
        return jsonify(dict(status=False, desc='策略不存在'))

    policy_name = policy.name
    policy_user = web_policy_user(policy_id)
    family_dict = web_policy_family(policy_id)
    vul_dict = {}
    for family_id in family_dict.keys():
        vul_dict[family_id] = web_policy_vul(policy_id, family_id)
    return render_template('policy_update.html', policy_id=policy_id, policy_name=policy_name, \
                           policy_user=policy_user, family_dict=family_dict, \
                           family_json=json.dumps(family_dict), vul_json=json.dumps(vul_dict))


# 提交修改方案内容
@web.route('/policy/update', methods=['POST'])
@login_required
@permission_required('edit_policy')
def policy_update():
    policy_id = request.values.get("policy_id")
    vul_result_json = request.values.get("vul_result_json")
    if not verify_webpolicyid(policy_id):  # policy_id在数据库里不存在
        return jsonify(dict(status=False, desc='方案不存在'))
    result = web_policy_update(policy_id, vul_result_json)
    return result


@web.route('/policy/script', methods=['GET', 'POST'])
@login_required
@permission_required('edit_policy')
def add_script():
    if request.method == 'POST':
        '''提交页面数据'''
        plug_name = request.values.get('plug_name')
        scan_type = request.values.get('scan_type')
        script_name = request.values.get('script_name')
        bug_level = request.values.get('bug_level')
        bug_desc = request.values.get('bug_desc')
        bug_solu = request.values.get('bug_solu')
        script_priority = request.values.get('script_priority')
        plug_type = request.values.get('plug_type')
        run_enable = 1 if request.values.get('run_enable') else 0
        # tag_label = request.values.get('tag_label')
        tag_label = ''  # tag标签在scan_site.py写入字典scan_cnf里面，此处停用。为不影响其他代码，暂时置空处理。
        # 规范传入参数，防止XSS
        plug_name = escape(plug_name.decode('utf-8'))
        script_name = escape(script_name.decode('utf-8'))
        bug_desc = escape(bug_desc.decode('utf-8'))
        bug_solu = escape(bug_solu.decode('utf-8'))


        vul_script = db.session.query(WebVulList).filter(WebVulList.script == script_name).first()
        if vul_script:
            return jsonify(dict(status=False, desc='插件已存在'))

        if plug_name == '' or scan_type == '' or script_name == '' or bug_level == '' or \
                        bug_desc == '' or bug_solu == '' or script_priority == '' or plug_type == '':
            return jsonify(dict(status=False, desc='参数无效'))

        try:
            r = add_policy_script(plug_name, scan_type, script_name, bug_level, bug_desc, bug_solu, script_priority,
                                  plug_type,
                                  None, None, run_enable, 0, None, None, None, tag_label)
            if r:
                return jsonify(dict(status=True, desc='提交成功'))
        except Exception as e:
            return jsonify(dict(status=False, desc='参数无效'))
    else:
        '''返回页面'''
        web_policys = db.session.query(WebVulFamily).filter(WebVulFamily.parent_id != 0)
        return render_template('web_script_add.html', policys=web_policys)


# 修改方案名称
@web.route('/policy/update_name', methods=['POST'])
@login_required
@permission_required('edit_policy')
def policy_name_update():
    policy_id = request.values.get("policy_id")
    new_policy_name = request.values.get("new_policy_name")
    new_policy_name = escape(new_policy_name.decode('utf-8'))
    if not new_policy_name:
        return jsonify(dict(status=False, desc='方案名不能为空'))
    if not verify_webpolicyid(policy_id):  # policy_id在数据库里不存在
        return jsonify(dict(status=False, desc='方案不存在'))
    result = web_policy_name_update(policy_id, new_policy_name)
    return result
