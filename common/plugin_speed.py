# --*-- coding: utf-8 --*--

from sqlalchemy import Column, String, Integer, Float
from sql_orm import Base


class PluginSpeed(Base):
    __tablename__ = 'plugin_speed'

    id = Column(Integer, primary_key=True, autoincrement=True)
    task_id = Column(Integer, nullable=True)
    vul_id = Column(Integer, nullable=True)
    duration = Column(Float, nullable=True)

    def __init__(self, task_id, vul_id, duration=0):
        self.task_id = task_id
        self.vul_id = vul_id
        self.duration = duration
