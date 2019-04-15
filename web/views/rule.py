# --*-- coding: utf-8 --*--
import json
from flask_login import login_required
from flask import redirect, render_template, request, url_for, jsonify
from web.utils.decorater import permission_required
from sqlalchemy import or_

from web import web, db
from web.models.rule import Rule, RuleFamily, WebRuleArea, WebRuleWay, WebRuleHttpCode, WebRuleTag, WebRuleRunMode
from web.models.web_policy_db import WebVulFamily, WebVulListCopy
from web.utils.paginate import get_page_items, get_pagination


@web.route('/rules')
@web.route('/rules/<int:rule_id>')
@login_required
@permission_required('edit_policy')
def rule_list(rule_id=None):
    search_msg = request.values.get('search_msg', '')
    rule_family = db.session.query(WebVulFamily).filter(WebVulFamily.parent_id != 0)

    ways = db.session.query(WebRuleWay)
    areas = db.session.query(WebRuleArea)
    http_codes = db.session.query(WebRuleHttpCode)
    tags = db.session.query(WebRuleTag)
    modes = db.session.query(WebRuleRunMode)
    if rule_id:
        rule = db.session.query(Rule).filter(Rule.rule_id == rule_id).first()
        return render_template('rule_edit.html', rule=rule, rule_family=rule_family, ways=ways, areas=areas,
                               http_codes=http_codes, tags=tags, modes=modes)
    page, per_page, offset, search_msg = get_page_items()

    query = db.session.query(Rule)
    if search_msg:
        like_msg = '%%%s%%' % search_msg
        query = query.filter(or_(Rule.rule_id.like(search_msg), Rule.rule_family.like(like_msg),
                                 Rule.rule_name.like(like_msg), Rule.inj_value.like(like_msg)))
    rules = query.limit(per_page).offset(offset).all()
    total = query.count()
    pagination = get_pagination(page=page,
                                per_page=per_page,
                                total=total,
                                record_name="server",
                                format_total=True,
                                format_number=True,
                                )
    return render_template('rule.html', pagination=pagination, rules=rules, rule_family=rule_family, ways=ways, areas=areas,
                           http_codes=http_codes, tags=tags, modes=modes, level_one='rule', level_two='list')


@web.route('/rules/add')
@login_required
@permission_required('edit_policy')
def rule_add_html():
    ways = db.session.query(WebRuleWay)
    areas = db.session.query(WebRuleArea)
    http_codes = db.session.query(WebRuleHttpCode)
    tags = db.session.query(WebRuleTag)
    modes = db.session.query(WebRuleRunMode)
    familys = db.session.query(WebVulFamily).filter(WebVulFamily.parent_id != 0)
    # vuls = db.session.query(WebVulListCopy).filter(WebVulListCopy.scan_type == 3).all()
    vul_list = []
    # for vul in vuls :
    #     vul_dict = {'id':vul.id, 'vul_id':vul.vul_id, 'vul_name':vul.vul_name, 'enable':vul.enable, 'family':vul.family, 'module':vul.module, 'scan_type':vul.scan_type, 'script':vul.script, 'level':vul.level, 'priority':vul.priority}    # print vul_list
    #     vul_list.append(vul_dict)
    # print json.dumps(vul_list)
    return render_template('rule_add.html', familys=familys, vuls=json.dumps(vul_list), ways=ways, areas=areas,
                           http_codes=http_codes, tags=tags, modes=modes)
