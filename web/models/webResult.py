# -*- coding: utf-8 -*-
from web import db


class WebResult(db.Model):
    __tablename__ = 'web_result'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 主键ID
    task_id = db.Column(db.Integer, nullable=False)  # 任务ID
    site_id = db.Column(db.Integer, nullable=False)  # 站点ID
    url = db.Column(db.String(128), nullable=False)  # URL
    level = db.Column(db.String(12), nullable=False)  # 风险等级，C：紧急，H：高危，M：中危，L：低风险，I：信息
    detail = db.Column(db.Text, nullable=False)  # 漏洞描述
    output = db.Column(db.String(512), nullable=False)  # 输出信息
    vul_id = db.Column(db.Integer, nullable=False)  # Web漏洞ID
    asset_task_id = db.Column(db.Integer, nullable=False)  # 资产管理扫描任务ID

    def __init__(self, task_id=0, site_id=0, url='', level='', detail='', output='', vul_id=0, asset_task_id=0):
        self.task_id = task_id  # 任务ID
        self.site_id = site_id  # 站点ID
        self.url = url  # URL
        self.level = level  # 风险等级，C：紧急，H：高危，M：中危，L：低风险，I：信息
        self.detail = detail  # 漏洞描述
        self.output = output  # 输出信息
        self.vul_id = vul_id  # Web漏洞ID
        self.asset_task_id = asset_task_id  # 资产管理扫描任务ID

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class WebResultData(db.Model):
    __tablename__ = 'web_result_data'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 主键ID
    web_result_id = db.Column(db.Integer, nullable=False)  # 任务ID
    request = db.Column(db.Text, nullable=False)  # 站点ID
    response = db.Column(db.Text, nullable=False)  # URL
    task_id = db.Column(db.Integer, nullable=False)  # 风险等级，C：紧急，H：高危，M：中危，L：低风险，I：信息
    asset_task_id = db.Column(db.Integer, nullable=False)  # 漏洞描述
    site_id = db.Column(db.Integer, nullable=False)  # 输出信息

    def __init__(self, web_result_id=0, request='', response='', task_id=0, asset_task_id=0, site_id=0):
        self.web_result_id = web_result_id  # 任务ID
        self.request = request  # 站点ID
        self.response = response  # URL
        self.task_id = task_id  # 风险等级，C：紧急，H：高危，M：中危，L：低风险，I：信息
        self.asset_task_id = asset_task_id  # 漏洞描述
        self.site_id = site_id  # 输出信息

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}
