
# from tasks.add import add_together
from web import web
from ext import celery


@celery.task(bind=True)
def run_add_together(self, a, b):
    print 0000000000000


# @web.route('/')
# def _index():
#     return 'Hello World!'
#
#
# @web.route('/web_job')
def add_job():
    job = run_add_together.apply_async(args=[3, 4], countdown=3)
    return job.id

if __name__ == '__main__':
    add_job()