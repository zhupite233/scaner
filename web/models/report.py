# -*- coding: utf-8 -*-
import json
from sqlalchemy import func, distinct
from web import db, logger
import sys
from web.models.task import Task
from web.models.webResult import WebResult
from web.models.web_policy_db import WebVulList

default_encoding = 'utf-8'
if sys.getdefaultencoding() != default_encoding:
    reload(sys)
    sys.setdefaultencoding(default_encoding)


class Report(db.Model):
    __tablename__ = 'report'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自增主键
    name = db.Column(db.String(256), default='', nullable=False)  # 报告名称
    domain = db.Column(db.String(50), default='', nullable=False)  # 域名
    task_id = db.Column(db.Integer, default=0, nullable=False)  # 任务ID
    job_id = db.Column(db.String(36), default='', nullable=False)  # 执行的任务ID
    pdf = db.Column(db.String(100), default="", nullable=False)  # PDF文件名
    json = db.Column(db.Text, default='', nullable=False)  # json格式数据
    json_raw = db.Column(db.Text, default='', nullable=False)  # 原始的JSON文件
    create_time = db.Column(db.TIMESTAMP, default='0000-00-00 00:00:00', nullable=False)  # 创建时间

    def __init__(self, name=None, domain=None, task_id=None, job_id=None, pdf=None, json=None, json_raw=None,
                 create_time=None):
        self.name = name
        self.domain = domain
        self.task_id = task_id
        self.job_id = job_id
        self.pdf = pdf
        self.json = json
        self.json_raw = json_raw
        self.create_time = create_time

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class PatchReport(db.Model):
    # id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自增主键
    patch_no = db.Column(db.String(50), primary_key=True, nullable=False)
    rep_json = db.Column(db.Text, nullable=True)
    task_ids = db.Column(db.Text, nullable=True)
    data_rep_json = db.Column(db.Text, nullable=True)
    notify_time = db.Column(db.DATETIME, nullable=True)

    def __init__(self, patch_no, re_json=None, task_ids='', data_rep_json='', notify_time=None):
        self.patch_no = patch_no
        self.rep_json = re_json
        self.task_ids = task_ids
        self.data_rep_json = data_rep_json
        self.notify_time = notify_time

    def gen_rep(self, update_task_id, domain=None):
        '''
        # 排名和分布生成累计数据
        {"ranking": {vul_family_name: {"count": 200, "url_count": 150}},
         "distribute": {www.baidu.com: {"HIGH": 5, "MED": 3, "LOW": 6}}
        }
         # over_view 只生成和传当前数据
          { www.baidu.com: {
             vul_name: {"count": 15, "urls": [], "level": "MED", "vul_desc": "", "vul_solu": ""}}
         }
        '''
        if not self.rep_json:
            rep_dict = {'ranking': {},
                        'distribute': {}
                        }
        else:
            rep_dict = json.loads(self.rep_json)
        if not domain:
            task = db.session.query(Task).filter(Task.id == update_task_id).first()
            domain = get_task_domain(task.target)
        try:

            # vuls = db.session.query(WebResult.url, WebResult.level, WebVulList.vul_name, WebVulList.family, WebVulList.desc,
            #                         WebVulList.solu).join(WebVulList, WebResult.vul_id == WebVulList.vul_id).filter(
            #     WebResult.task_id == update_task_id).all()
            # statistic the ranking
            ranking_res = db.session.query(WebVulList.family, func.count('1'), func.count(distinct(WebResult.url))).join(
                WebResult, WebResult.vul_id == WebVulList.vul_id).filter(WebResult.task_id == update_task_id).\
                group_by(WebVulList.family).all()
            for family_count in ranking_res:
                count = family_count[1]
                url_count = family_count[2]
                if rep_dict['ranking'].get(family_count[0]):
                    count = rep_dict['ranking'][family_count[0]]['count'] + count
                    url_count = rep_dict['ranking'][family_count[0]]['url_count'] + url_count
                rep_dict['ranking'][family_count[0]] = {"count": count, "url_count": url_count}
            #  static distribute
            d_dis = {"HIGH": 0, "MED": 0, "LOW": 0}
            dis_res = db.session.query(WebResult.level, func.count(1)).filter(WebResult.task_id==update_task_id).\
                group_by(WebResult.level).all()
            for dis_count in dis_res:
                d_dis[dis_count[0]] = dis_count[1]
            rep_dict['distribute'][domain] = d_dis
            # static overview
            v_dict = {}
            over_view_res = db.session.query(WebVulList.vul_name, func.count(1), WebVulList.level, func.concat(
                WebResult.url), WebVulList.desc, WebVulList.solu).join(
                WebResult, WebResult.vul_id == WebVulList.vul_id).filter(WebResult.task_id == update_task_id).\
                group_by(WebVulList.vul_name).all()
            for vul in over_view_res:
                v_dict[vul[0]] = {"count": vul[1], "level": vul[2], "urls": vul[3],  "vul_desc": vul[4], "vul_solu": vul[5]}
            over_view_dict = {domain: v_dict}
        except Exception, e:
            logger.error(e)
            over_view_dict = {}
        # print rep_dict['over_view']['demo.aisec.cn']['点击劫持']
        return rep_dict, over_view_dict, domain


def get_task_domain(target):
    try:
        targets = json.loads(target)
        domains = ''
        for target in targets:
            domains += ',' + target.get('domain')
        return domains.lstrip(',')
    except Exception, e:
        return ''


class PatchTask(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自增主键
    task_id = db.Column(db.Integer, nullable=False)
    patch_no = db.Column(db.String(50), nullable=False)
    notify_state = db.Column(db.Integer, default=0)  # 0: 未通知 1：通知成功 2：通知失败
    notify_msg = db.Column(db.Text, nullable=True)
    rep_state = db.Column(db.Integer, default=0)  # 0: 未update 1：update成功 2：update失败
    notify_time = db.Column(db.DATETIME, nullable=True)
    task_rep_json = db.Column(db.Text, nullable=True)
    domain = db.Column(db.String(250), nullable=True)
    data_rep_json = db.Column(db.Text, nullable=True)

    def __init__(self, task_id, patch_no, notify_state=0, notify_msg=None, rep_state=0, notify_time=None,
                 task_rep_json=None, domain=None, data_rep_json=''):
        self.task_id = task_id
        self.patch_no = patch_no
        self.notify_msg = notify_msg
        self.notify_state = notify_state
        self.rep_state = rep_state
        self.notify_time = notify_time
        self.task_rep_json = task_rep_json
        self.domain = domain
        self.data_rep_json = data_rep_json


class ReportModel(db.Model):
    '''
    自定义PDF报告模板
    '''
    __tablename__ = 'report_model'

    model_id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自增主键
    model_name = db.Column(db.String(100), nullable=False)  # 模板名称
    title = db.Column(db.String(100), nullable=True)  # 标题
    company = db.Column(db.String(100), nullable=True)  # 单位名称
    logo_filename = db.Column(db.String(100), nullable=True)  # logo 图片文件名
    footer = db.Column(db.String(100), nullable=True)  # 页脚
    user_id = db.Column(db.Integer, nullable=True)  # 创建该模板的用户ID

    def __init__(self, model_name, title, company, logo_filename, footer, user_id=None):
        self.model_name = model_name
        self.title = title
        self.company = company
        self.logo_filename = logo_filename
        self.footer = footer
        self.user_id = user_id

    def to_dict(self):
        return dict(model_id=self.model_id, model_name=self.model_name, title=self.title,
                    company=self.company, footer=self.footer)