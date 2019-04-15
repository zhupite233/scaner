# --*-- coding:utf-8 --*--
from create_app import create_app
app = create_app()
from ext import celery
celery.conf.update(app.config)
app.app_context().push()