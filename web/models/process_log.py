# --*-- coding: utf-8 --*--
from web import db


class ProcessRecord(db.Model):
    '''
    记录敏感操作日志
    '''
    __tablename__ = 'process_record'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)  # 自增主键
    task_id = db.Column(db.Integer, nullable=False)  # 扫描任务id
    user_id = db.Column(db.Integer, nullable=False)  # 操作者的user_id
    user_name = db.Column(db.String(15), nullable=True)  # 操作者的user_name
    url = db.Column(db.String, nullable=True)  # 请求url
    body = db.Column(db.String, nullable=True)  # 请求body
    process_desc = db.Column(db.String, nullable=True)  # 操作描述