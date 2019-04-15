# # -*- coding: utf-8 -*-
#
# from app import db
#
# class SpiderUrlOther(db.Model):
#     __tablename__ = "spider_url_other"
#
#
#     id = db.Column(db.Integer, primary_key=True, autoincrement=True) # 自增id
#     task_id = db.Column(db.Integer, nullable=False, default=0)  # 扫描任务id
#     site_id = db.Column(db.Integer, nullable=False, default=0)  #扫描网站id
#     url = db.Column(db.String(512), nullable=False)  # 请求url
#     params = db.Column(db.TEXT, nullable=False)  # 请求参数
#     method = db.Column(db.String(5), nullable=False)  # 请求方法
#     refer = db.Column(db.String(512), nullable=False)  # 来源路径 应该允许为空
#     pattern_path = db.Column(db.String(256), nullable=True)  # 路径模式
#     pattern_params = db.Column(db.String(256), nullable=True)  # 参数模式
#     asset_task_id = db.Column(db.Integer, nullable=False, default=0)
#     type = db.Column(db.SmallInteger, nullable=False)  # 0死链，1外链，2其他异常
#
#     def __init__(self, task_id, site_id, url, params, refer, pattern_path, pattern_params, asset_task_id, type):
#         self.task_id = task_id
#         self.site_id = site_id
#         self.url = url
#         self.params = params
#         self.refer = refer
#         self.pattern_path = pattern_path
#         self.pattern_params = pattern_params
#         self.asset_task_id = asset_task_id
#         self.type = type
#
