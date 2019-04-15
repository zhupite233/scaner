# --*-- coding: utf-8 --*--
from flask_script import Command
from web import db
from web.models.user import Role, Group
from web.models.cron import JobStatus
from web.models.task import TaskWebScheme
from web.models.rule import WebRuleHttpCode


def init_role():
    defaults = (
        (1, 'ADMIN', '管理员'),
        (2, 'CU', '普通用户'),
        (3, 'GUEST', '游客'),
    )
    for role_id, name, cname in defaults:
        role = Role(role_id, name, cname)

        db.session.add(role)
    db.session.commit()


def init_group():
    defaults = (
        ('ADMIN', '管理员', '*'),

    )
    for name, cname, selectors in defaults:
        group = Group(name, cname, selectors)
        db.session.add(group)
    db.session.commit()


def init_job_status():
    defaults = (
        (1, '未执行'),
        (2, '执行中'),
        (3, '完成'),
        (4, '暂停'),
        (5, '失败')
    )
    for status_id, status_name in defaults:
        job_status = JobStatus(status_id, status_name)
        db.session.add(job_status)
    db.session.commit()


def init_scheme():
    defaults = (
        ('http', 'http'),
        ('https', 'https'),
    )
    for scheme_name, scheme_desc in defaults:
        scheme = TaskWebScheme(scheme_name, scheme_desc)
        db.session.add(scheme)
    db.session.commit()


def init_http_code():
    defaults = (

        ('100', 'Continue',),
        ('101', 'Switching Protocols',),
        ('200', 'OK',),
        ('201', 'Created',),
        ('202', 'Accepted',),
        ('203', 'Non-Authoritative Information',),
        ('204', 'No Content',),
        ('205', 'Reset Content',),
        ('206', 'Partial Content',),
        ('300', 'Multiple Choices',),
        ('301', 'Moved Permanently',),
        ('302', 'Found',),
        ('303', 'See Other',),
        ('304', 'Not Modified',),
        ('305', 'Use Proxy',),
        ('307', 'Temporary Redirect',),
        ('400', 'Bad Request',),
        ('401', 'Unauthorized',),
        ('403', 'Forbidden',),
        ('404', 'Not Found',),
        ('405', 'Method Not Allowed',),
        ('406', 'Not Acceptable',),
        ('407', 'Proxy Authentication Required',),
        ('408', 'Request Timeout',),
        ('409', 'Conflict',),
        ('410', 'Gone',),
        ('411', 'Length Required',),
        ('412', 'Precondition Failed',),
        ('413', 'Request Entity Too Large',),
        ('414', 'Request URI Too Long',),
        ('415', 'Unsupported Media Type',),
        ('416', 'Requested Range Not Satisfiable',),
        ('417', 'Expectation Failed',),
        ('461', 'Intercept by YUNDUN WAF',),
        ('500', 'Internal Server Error',),
        ('501', 'Not Implemented',),
        ('502', 'Bad Gateway',),
        ('503', 'Service Unavailable',),
        ('504', 'Gateway Timeout',),
        ('505', 'HTTP Version Not Supported'),

    )
    for code, info in defaults:
        http_code = WebRuleHttpCode(code, info)
        db.session.add(http_code)
    db.session.commit()


def main():
    init_role()
    # init_group()
    # init_scheme()
    # init_http_code()


if __name__ == '__main__':
    main()
