# --*-- coding: utf-8 --*--
from sqlalchemy import Column, String, Integer, Text, DATE
from sql_orm import Base


class CnnvdVul(Base):
    __tablename__ = 'cnnvd_vul'
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(50))
    cnnvd_id = Column(String(50))
    cve_id = Column(String(50), nullable=True)
    vul_id = Column(Integer, nullable=True)
    pub_date = Column(DATE, nullable=True)
    mod_date = Column(DATE, nullable=True)
    vul_type = Column(String(50), nullable=True)
    remote = Column(String(10), nullable=True)
    level = Column(String(10), nullable=True)
    yundun = Column(Integer, nullable=True)
    web_vul = Column(Integer, nullable=True)
    desc = Column(Text, nullable=True)
    solu = Column(Text, nullable=True)

    def __init__(self, name=name, cnnvd_id=cnnvd_id, cve_id=cve_id, vul_id=vul_id, pub_date=pub_date, remote=remote,
                 web_vul=web_vul, yundun=yundun,
                 mod_date=mod_date, vul_type=vul_type, level=level, desc=desc, solu=solu):
        self.name = name
        self.cnnvd_id = cnnvd_id
        self.cve_id = cve_id
        self.vul_id = vul_id
        self.pub_date = pub_date
        self.mod_date = mod_date
        self.vul_type = vul_type
        self.level = level
        self.web_vul = web_vul
        self.yundun = yundun
        self.remote = remote
        self.desc = desc
        self.solu = solu