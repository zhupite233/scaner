from flask_script import Command
from db_init import main
from db_create import create_db
"""
    usage: python manage.py init_db|create_db
"""


class InitDataBase(Command):

    def run(self):
        main()


class CreateDB(Command):

    def run(self):
        create_db()