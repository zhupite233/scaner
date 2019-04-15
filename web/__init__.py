# coding=utf-8

from flask import Blueprint

from common.logger import Logger
from ext import login_manager, db, principal

web = Blueprint('web', __name__, template_folder='templates', static_folder='static')

login_manager.session_protection = 'strong'
login_manager.login_view = 'web.do_login'

logger = Logger('web_scan_')

from views import *
from web.utils.templatetags.mytags import *
from . import new_tasks

