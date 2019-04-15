# -*- coding: utf-8 -*-

from web import db


class WebVulPolicy(db.Model):
    __tablename__ = "web_vul_policy"

    # 方案id
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # 源码的数据库web_vul_policy的name字段允许为空，应该改过来
    name = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, nullable=True)

    def __init__(self, policy_name, user_id):
        self.name = policy_name
        self.user_id = user_id


class WebVulPolicyRef(db.Model):
    __tablename__ = "web_vul_policy_ref"

    # 方案id
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    # 源码是允许为空，应该改
    policy_id = db.Column(db.Integer, nullable=True)
    family_id = db.Column(db.Integer, nullable=True)
    vul_id = db.Column(db.Integer, nullable=True)

    def __init__(self, policy_id, family_id, vul_id):
        self.policy_id = policy_id
        self.family_id = family_id
        self.vul_id = vul_id


class WebVulList(db.Model):
    __tablename__ = "web_vul_list"

    # id和vul_id的值相等
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vul_id = db.Column(db.Integer, nullable=True)  # 源码是允许为空，应该改
    vul_name = db.Column(db.String(255), nullable=True)
    enable = db.Column(db.Integer, nullable=True)
    family = db.Column(db.String(255), nullable=True)
    family_id = db.Column(db.Integer, nullable=True)
    module = db.Column(db.String(255), nullable=True)
    module_id = db.Column(db.Integer, nullable=True)
    scan_type = db.Column(db.Integer, nullable=True)
    script = db.Column(db.String(100), nullable=True)
    level = db.Column(db.String(10), nullable=True)

    effect = db.Column(db.TEXT, nullable=True)
    reference = db.Column(db.TEXT, nullable=True)

    desc = db.Column(db.TEXT, nullable=True)
    solu = db.Column(db.TEXT, nullable=True)
    soluid = db.Column(db.Integer, nullable=True)
    priority = db.Column(db.Integer, nullable=True)
    tag = db.Column(db.TEXT, nullable=True)

    def __init__(self, vul_id, vul_name, enable, family, module, scan_type, script,
                 level, desc, solu, soluid, priority, tag=None, family_id=None, module_id=None, effect=None,
                 reference=None, ):
        self.vul_id = vul_id
        self.vul_name = vul_name
        self.enable = enable
        self.family = family
        self.module = module
        self.scan_type = scan_type
        self.script = script
        self.level = level
        self.effect = effect
        self.reference = reference
        self.desc = desc
        self.solu = solu
        self.soluid = soluid
        self.priority = priority
        self.tag = tag
        self.family_id = family_id
        self.module_id = module_id

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class WebVulListCopy(db.Model):
    __tablename__ = "web_vul_list_copy"

    # id和vul_id的值相等
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vul_id = db.Column(db.Integer, nullable=True)  # 源码是允许为空，应该改
    vul_name = db.Column(db.String(255), nullable=True)
    enable = db.Column(db.Integer, nullable=True)
    family = db.Column(db.String(255), nullable=True)

    module = db.Column(db.String(255), nullable=True)

    scan_type = db.Column(db.Integer, nullable=True)
    script = db.Column(db.String(100), nullable=True)
    level = db.Column(db.String(10), nullable=True)

    desc = db.Column(db.TEXT, nullable=True)
    solu = db.Column(db.TEXT, nullable=True)
    soluid = db.Column(db.Integer, nullable=True)
    priority = db.Column(db.Integer, nullable=True)


class WebVulFamily(db.Model):
    __tablename__ = "web_vul_family"

    # family_id
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    parent_id = db.Column(db.Integer, nullable=True)  # 源码是允许为空，应该改
    desc = db.Column(db.String(255), nullable=True)
    priority = db.Column(db.Integer, nullable=True)

    def __init__(self, module, description, priority):
        self.parent_id = module
        self.desc = description
        self.priority = priority


class WebVulFamilyRef(db.Model):
    __tablename__ = "web_vul_family_ref"

    # family_ref_id 自增的 无特殊意义
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    module = db.Column(db.Integer, nullable=True)  # 源码是允许为空，应该改
    family = db.Column(db.Integer, nullable=True)
    vul_id = db.Column(db.Integer, nullable=True)

    def __init__(self, module, family_id, vul_id):
        self.module = module
        self.family = family_id
        self.vul_id = vul_id
