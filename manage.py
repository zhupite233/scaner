# --*-- coding: utf-8 --*--

from flask_script import Manager
from create_app import create_app

app = create_app()

manager = Manager(app)

if __name__ == '__main__':
    from scripts.db_init_command import InitDataBase, CreateDB
    manager.add_command('init_db', InitDataBase())
    manager.add_command('create_db', CreateDB())
    manager.run()
