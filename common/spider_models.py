# --*-- coding: utf-8 --*--
from sqlalchemy import Column, String, Integer, Text
from sql_orm import Base


class ScanSpiderUrl(Base):
    __tablename__ = 'scan_spider_url'
    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=True)
    site_id = Column(Integer, nullable=True)
    url = Column(Text, nullable=True)
    params = Column(Text, nullable=True)
    method = Column(String(5), nullable=True)
    refer = Column(Text, default='', nullable=True)
    asset_task_id = Column(Integer, nullable=True)
    url_dir = Column(String(256), nullable=True)
    url_ext = Column(String(32), nullable=True)
    params_keys = Column(String(256), nullable=True)

    def __init__(self, task_id=0, url='', site_id=0, params='', method='GET', refer='', asset_task_id=0
                 , url_dir='', url_ext='', params_keys=''):
        self.task_id = task_id
        self.url = url
        self.site_id = site_id
        self.params = params
        self.method = method
        self.refer = refer
        self.asset_task_id = asset_task_id
        self.url_dir = url_dir
        self.url_ext = url_ext
        self.params_keys = params_keys


class ScanSpiderUrlOther(Base):
    __tablename__ = "scan_spider_url_other"

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=True)
    site_id = Column(Integer, nullable=True)
    url = Column(String(512), nullable=False)
    params = Column(Text, nullable=True)
    method = Column(String(5), nullable=True)
    refer = Column(String(512), nullable=True)
    pattern_path = Column(String(256), nullable=True)
    pattern_params = Column(String(256), nullable=True)
    asset_task_id = Column(Integer, nullable=True)
    type = Column(Integer, nullable=True)  # 0死链，1外链，2其他异常

    def __init__(self, task_id, url, method='get', params='', refer='',  site_id=0, pattern_path='',
                 pattern_params='', asset_task_id=0, type=1):
        self.task_id = task_id
        self.site_id = site_id
        self.url = url
        self.params = params
        self.method = method
        self.refer = refer
        self.pattern_path = pattern_path
        self.pattern_params = pattern_params
        self.asset_task_id = asset_task_id
        self.type = type


class WebVulList(Base):
    __tablename__ = "web_vul_list"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vul_id = Column(Integer, nullable=True)
    vul_name = Column(String(255), nullable=True)
    enable = Column(Integer, nullable=True)
    family_id = Column(Integer, nullable=True)
    family = Column(String(255), nullable=True)
    module_id = Column(Integer, nullable=True)
    module = Column(String(255), nullable=True)
    scan_type = Column(Integer, nullable=True)
    script = Column(String(100), nullable=True)
    level = Column(String(10), nullable=True)
    effect = Column(Text, default='', nullable=True)
    reference = Column(Text, default='', nullable=True)
    desc = Column(Text, default='', nullable=True)
    solu = Column(Text, default='', nullable=True)
    soluid = Column(Integer, nullable=True)
    priority = Column(Integer, nullable=True)
    tag = Column(String(50), nullable=True)

    def __init__(self, id, vul_id, vul_name, enable, family_id, family, module_id, module, scan_type,
                 script, level, effect, reference, desc, solu, soluid, priority, tag):
        self.id = id
        self.vul_id = vul_id
        self.vul_name = vul_name
        self.enable = enable
        self.family_id = family_id
        self.family = family
        self.module_id = module_id
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