# --*-- coding: utf-8 --*--
from web import db


class RuleFamily(db.Model):
    __tablename__ = 'web_rule_family'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(50), nullable=False)
    describe = db.Column(db.Text, nullable=True)
    priority = db.Column(db.Integer, nullable=True)
    # rules = db.relationship('Rule', backref='family_rules', lazy='dynamic')

    def __init__(self, name, describe, priority):
        self.name = name
        self.describe = describe
        self.priority = priority


class Rule(db.Model):
    __tablename__ = 'web_scan_rule'

    rule_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    rule_family = db.Column(db.Integer, nullable=False)

    rule_tag = db.Column(db.String(50), nullable=True)
    rule_name = db.Column(db.String(50), nullable=True)
    rule_json = db.Column(db.Text, nullable=True)
    area = db.Column(db.String(50), nullable=False)
    inj_way = db.Column(db.String(50), nullable=False)
    inj_point = db.Column(db.String(250), nullable=False)
    inj_value = db.Column(db.Text, nullable=False)
    judge = db.Column(db.String(250), nullable=False)
    describe = db.Column(db.Text, nullable=False)
    run_mode = db.Column(db.String(50), nullable=False)
    if_head = db.Column(db.Boolean, default=False)
    vul_id = db.Column(db.Integer, nullable=True)

    def __init__(self, rule_family, rule_name, rule_json, area, inj_way, inj_point, inj_value, judge,
                 describe, run_mode, rule_tag=None, if_head=False, vul_id=0):
        self.rule_family = rule_family
        self.rule_name = rule_name
        self.rule_json = rule_json
        self.area = area
        self.inj_way = inj_way
        self.inj_point = inj_point
        self.inj_value = inj_value
        self.judge = judge
        self.describe = describe
        self.run_mode = run_mode
        self.rule_tag = rule_tag
        self.if_head = if_head
        self.vul_id = vul_id


class WebRuleArea(db.Model):
    __tablename__ = 'web_rule_area'
    rule_area = db.Column(db.String(50), primary_key=True)


class WebRuleWay(db.Model):
    __tablename__ = 'web_rule_way'

    rule_way = db.Column(db.String(50), primary_key=True)
    describe = db.Column(db.String(50), primary_key=True)


class WebRuleTag(db.Model):
    __tablename__ = 'web_rule_tag'
    rule_tag = db.Column(db.String(50), primary_key=True)


class WebRuleHttpCode(db.Model):
    __tablename__= 'web_rule_http_code'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    http_code = db.Column(db.Integer, nullable=False)
    code_info = db.Column(db.String(200))

    def __init__(self, http_code, code_info):
        self.http_code = http_code
        self.code_info = code_info


class WebRuleRunMode(db.Model):
    __tablename__ = 'web_rule_run_mode'
    run_mode = db.Column(db.String(50), primary_key=True)


class TaskRuleFamilyRef(db.Model):
    __tablename__ = 'task_rule_family_ref'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, nullable=False)
    rule_family_id = db.Column(db.Integer, nullable=False)

    def __init__(self, task_id, rule_family_id):
        self.task_id = task_id
        self.rule_family_id = rule_family_id
