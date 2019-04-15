# -*- coding: utf-8 -*-
__author__ = 'ArthurMok'
from flask import Blueprint
api = Blueprint('api', __name__)

from . import user, web_task, report, web_policy_api, rule, spider_api, tsgz_report
