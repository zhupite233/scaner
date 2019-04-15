# --*-- coding: utf-8 --*--
from functools import wraps
from flask import session, abort, request, redirect, url_for
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from web.models.cron import SpiderJob
from web.models.user import TokenMapping, User
from web import db
from web.utils.logger import mylogger as logger
from config import SECRET_KEY, SESSION_LIFETIME

def permission_required(privilege):
    def validate_permission(f):
        @wraps(f)
        def decorated_validate(*args, **kwargs):
            if privilege in session.get('selectors', ()):
                return f(*args, **kwargs)
            abort(403)

        return decorated_validate

    return validate_permission


def permission_required_notify(privilege):
    def validate_permission(f):
        @wraps(f)
        def decorated_validate(*args, **kwargs):

            token = request.values.get('token')

            if 'spider_notify' == privilege and verify_token(token):
                return f(*args, **kwargs)
            abort(403)

        return decorated_validate

    return validate_permission


def verify_token(token):
    spider_job = db.session.query(SpiderJob).filter(SpiderJob.token == token).first()
    if spider_job and spider_job.notify_times > 0:
        return True
    else:
        return False


def permission_required_inter(privilege):
    def validate_permission(f):
        @wraps(f)
        def decorated_validate(*args, **kwargs):
            if privilege in session.get('selectors', ()):
                return f(*args, **kwargs)

            scan_key = request.values.get('scan_key')

            if scan_key and verify_scan_key(scan_key):
                return f(*args, **kwargs)
            abort(403)

        return decorated_validate

    return validate_permission


def verify_scan_key(key):
    try:
        s = Serializer(SECRET_KEY, expires_in=SESSION_LIFETIME)
        token = db.session.query(TokenMapping).filter(TokenMapping.uuid == key).first().token
        user_json = s.loads(token)
        name = user_json['name']
        user = db.session.query(User).filter(User.name == name, User.status == 1).first()

        if user:
            return user
        else:
            return None
    except Exception, e:
        logger.exception(e)
        return None
