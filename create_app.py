# --*-- coding:utf-8 --*--
from ext import db, principal, login_manager, app

from web import web
# from host_scan import host
# from port_scan import port
from engine import engine

from web.api_1_0 import api as web_api_1_0_blueprint


def create_app():
    app.config.from_object('config')
    app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', True)
    app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024  # logo文件最大不能超过3M，否则返回413状态码
    db.init_app(app)

    principal.init_app(app)
    login_manager.init_app(app)
    app.register_blueprint(web, url_prefix='')  # url_prefix 不能为'/'
    app.register_blueprint(web_api_1_0_blueprint, url_prefix='/api/v1')
    # app.register_blueprint(host, url_prefix='/host_scan')
    # app.register_blueprint(port, url_prefix='/port_scan')
    app.register_blueprint(engine)

    return app
