# -*- coding: utf-8 -*-
from web import db
import sys

default_encoding = 'utf-8'
if sys.getdefaultencoding() != default_encoding:
    reload(sys)
    sys.setdefaultencoding(default_encoding)


class Task(db.Model):
    __tablename__ = 'task'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自增主键
    name = db.Column(db.String(256), default='', nullable=False)  # 任务名称
    target = db.Column(db.Text, nullable=False)  # 任务目标
    state = db.Column(db.SmallInteger, default=0, nullable=False)  # 扫描状态 job_status 表对应
    init_state = db.Column(db.Integer, default=1, nullable=False)  # 初始化状态
    prescan_state = db.Column(db.Integer, default=1, nullable=False)  # 预扫描状态

    c_vul_count = db.Column(db.Integer, default=0, nullable=False)  # 紧急漏洞数量
    h_vul_count = db.Column(db.Integer, default=0, nullable=False)  # 高危漏洞数量
    m_vul_count = db.Column(db.Integer, default=0, nullable=False)  # 中危漏洞数量
    l_vul_count = db.Column(db.Integer, default=0, nullable=False)  # 低危漏洞数量
    i_vul_count = db.Column(db.Integer, default=0, nullable=False)  # 信息数量

    start_time = db.Column(db.DateTime, default='0000-00-00 00:00:00', nullable=False)  # 开始扫描时间
    end_time = db.Column(db.DateTime, default='0000-00-00 00:00:00', nullable=False)  # 结束扫描时间
    schedule = db.Column(db.String(128), default='', nullable=False)  # 计划任务

    spider_enable = db.Column(db.SmallInteger, default='1', nullable=False)  # 是否开启爬虫
    spider_url_count = db.Column(db.Integer, default='200', nullable=False)  # 爬虫最大抓取页面数量
    spider_state = db.Column(db.SmallInteger, default='0', nullable=False)  # 爬虫状态
    spider_type = db.Column(db.SmallInteger, default='0', nullable=False)  # 爬虫类型

    web_scan_enable = db.Column(db.SmallInteger, default='0', nullable=False)  # 是否扫描Web漏洞。1：开启，0：关闭
    web_scan_state = db.Column(db.SmallInteger, default='0', nullable=False)  # Web扫描状态，1：已完成，0：未完成
    web_scan_thread = db.Column(db.Integer, default='1', nullable=False)  # Web扫描线程数量
    web_scan_policy = db.Column(db.Integer, default='0', nullable=False)  # Web扫描策略
    web_scan_timeout = db.Column(db.Integer, default='10', nullable=False)  # web扫描超时时间，单位秒
    web_search_site_state = db.Column(db.SmallInteger, default='0', nullable=False)  # 获取域名状态
    web_search_site_timeout = db.Column(db.Integer, default='30', nullable=False)  # 搜索站点超时时间

    weak_pwd_scan_enable = db.Column(db.SmallInteger, default='0', nullable=False)  # 弱密码扫描开关，1：开启，0：关闭
    weak_pwd_scan_state = db.Column(db.SmallInteger, default='0', nullable=False)  # 弱密码扫描状态，1：已完成，0：未完成
    weak_pwd_scan_thread = db.Column(db.Integer, default='5', nullable=False)  # 弱密码扫描线程数
    weak_pwd_scan_policy = db.Column(db.String(64), default='', nullable=False)  # 弱密码扫描策略
    weak_pwd_scan_timeout = db.Column(db.Integer, default='30', nullable=False)  # 弱密码扫描超时

    port_scan_enable = db.Column(db.SmallInteger, default='0', nullable=False)  # 端口扫描开关。1：开启，0：关闭
    port_scan_state = db.Column(db.SmallInteger, default='0', nullable=False)  # 端口扫描状态，1：已完成，0：未完成
    port_scan_timeout = db.Column(db.Integer, default='30', nullable=False)  # 弱密码扫描超时
    port_scan_thread = db.Column(db.SmallInteger, default='5', nullable=False)  # 端口扫描线程数量
    port_scan_policy = db.Column(db.Integer, default='0', nullable=False)  # 端口扫描策略

    host_scan_enable = db.Column(db.SmallInteger, default='0', nullable=False)  # 是否开启主机扫描
    host_scan_state = db.Column(db.SmallInteger, default='0', nullable=False)  # 主机扫描状态
    host_scan_thread = db.Column(db.Integer, default='1', nullable=False)  # 主机扫描进程
    host_scan_timeout = db.Column(db.Integer, default='60', nullable=False)  # 主机扫描超时
    host_scan_policy = db.Column(db.Integer, default='0', nullable=False)  # 主机扫描策略
    host_scan_max_script = db.Column(db.Integer, default='0', nullable=False)  # 主机扫描数量

    user_id = db.Column(db.Integer, default='0', nullable=False)  # 用户ID
    email = db.Column(db.String(128), default='', nullable=False)  # 通知邮件
    host_scan_uuid = db.Column(db.String(128), default='0', nullable=False)  # 主机扫描标识
    asset_task_id = db.Column(db.Integer, default='0', nullable=False)  # 资产管理扫描任务ID

    def formatStartTime(self):
        return self.start_time if self.start_time else ''

    def formatEndTime(self):
        return self.end_time if self.end_time else ''

    def explainState(self):
        if self.state == 0:
            return "未扫描"
        elif self.state == 1:
            return "未扫描"
        elif self.state == 2:
            return "扫描异常"
        elif self.state == 3:
            return "扫描完成"
        else:
            return str(self.state)

    def to_dict(self):
        return {c.name: getattr(self, c.name, None) for c in self.__table__.columns}


class TaskWebScheme(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scheme_name = db.Column(db.String(50), nullable=False)
    scheme_desc = db.Column(db.String(250), nullable=True)

    def __init__(self, scheme_name, scheme_desc=None):
        self.scheme_name = scheme_name
        self.scheme_desc = scheme_desc


class Sites(db.Model):
    __tablename__ = 'sites'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, default=0, nullable=False)
    title = db.Column(db.String(128), default='', nullable=False)
    scheme = db.Column(db.String(6), default='', nullable=False)
    domain = db.Column(db.String(128), default='', nullable=False)
    path = db.Column(db.String(128), default='', nullable=False)
    ip = db.Column(db.String(45), default='', nullable=False)
    site_type = db.Column(db.String(16), default='', nullable=False)
    state = db.Column(db.Integer, default=0, nullable=False)
    spider_state = db.Column(db.Integer, default=0, nullable=False)
    progress = db.Column(db.Text, default='', nullable=False)
    exception = db.Column(db.Text, default='', nullable=False)
    exception_count = db.Column(db.Integer, default=0, nullable=False)
    policy = db.Column(db.Integer, default=0, nullable=False)
    start_time = db.Column(db.DateTime, default='0000-00-00 00:00:00', nullable=False)
    end_time = db.Column(db.DateTime, default='0000-00-00 00:00:00', nullable=False)
    next_start_time = db.Column(db.DateTime, default='0000-00-00 00:00:00', nullable=False)
    cookie = db.Column(db.Text, default='', nullable=False)
    include_url = db.Column(db.Text, default='', nullable=False)
    exclude_url = db.Column(db.Text, default='', nullable=False)
    sub_domain_scan = db.Column(db.Integer, default=0, nullable=False)
    ip_domain_scan = db.Column(db.Integer, default=0, nullable=False)
    asset_task_id = db.Column(db.Integer, default=0, nullable=False)


class SpiderUrl(db.Model):
    __tablename__ = 'spider_url'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, default=0, nullable=False)
    site_id = db.Column(db.Integer, default=0, nullable=False)
    url = db.Column(db.Text, default='', nullable=False)
    params = db.Column(db.Text, default='', nullable=False)
    method = db.Column(db.String(5), default='', nullable=False)
    refer = db.Column(db.Text, default='', nullable=False)
    asset_task_id = db.Column(db.Integer, default=0, nullable=False)

    def __init__(self, task_id, url, site_id=0, params='', method='get', refer=None, asset_task_id=None):
        self.task_id = task_id
        self.url = url
        self.site_id = site_id
        self.params = params
        self.method = method
        self.refer = refer
        self.asset_task_id = asset_task_id


class TaskRepModelRef(db.Model):
    __tablename__ = 'task_rep_model_ref'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    task_id = db.Column(db.Integer, default=0, nullable=False)
    rep_model_id = db.Column(db.Integer, default=0, nullable=False)

    def __init__(self, task_id, rep_model_id):
        self.task_id = task_id
        self.rep_model_id = rep_model_id