from celery import Celery, platforms
from config import CELERY_BROKER_URL, CELERY_RESULT_BACKEND, CELERY_QUEUES, CELERY_ROUTES


def make_celery(app):
    celery = Celery(app.import_name, broker=CELERY_BROKER_URL)
    platforms.C_FORCE_ROOT = True
    celery.conf.update(CELERY_QUEUES=CELERY_QUEUES, CELERY_ROUTES=CELERY_ROUTES)
    TaskBase = celery.Task

    class ContextTask(TaskBase):
        abstract = True

        def __call__(self, *args, **kwargs):
            with app.app_context():
                return TaskBase.__call__(self, *args, **kwargs)
    celery.Task = ContextTask
    return celery
