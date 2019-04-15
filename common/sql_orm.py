# --*-- coding: utf-8 --*--

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.ext.declarative import declarative_base
from config import DB_NAME, DB_PORT, DB_HOST, DB_PASSWORD, DB_USERNAME
# 创建对象的基类:
Base = declarative_base()

# 初始化数据库连接:
DB_CONNECT_STRING = 'mysql+mysqlconnector://%s:%s@%s:%s/%s' % (DB_USERNAME, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME)
engine = create_engine(DB_CONNECT_STRING, pool_recycle=3600)
# 创建DBSession类型:
# DBSession = sessionmaker(bind=engine)
DBSession = scoped_session(sessionmaker(bind=engine))