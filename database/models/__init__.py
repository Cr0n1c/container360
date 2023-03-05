import hashlib 

from sqlalchemy import Column, Integer, String, PickleType
from sqlalchemy.orm import Session

from database import Base

class ScanQueue(Base):
    __tablename__ = 'scan_queue'

    id = Column(Integer, primary_key=True, index=True)
    image_uuid = Column(String, unique=True, index=True)
    image_name = Column(String)
    image_tag = Column(String)

class ScanResults(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    image_uuid = Column(String, unique=True, index=True)
    image_name = Column(String)
    image_tag = Column(String)
    image_alerts = Column(PickleType)


class ImageRunningProcesses(Base):
    __tablename__ = "running_processes"

    id = Column(Integer, primary_key=True, index=True)
    image_uuid = Column(String, index=True)
    pid = Column(String)
    user = Column(String)
    time = Column(String)
    command = Column(String)


class ImageNetworkConnections(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    image_uuid = Column(String, index=True)
    protocol = Column(String)
    recv_q = Column(String)
    send_q = Column(String)
    local_ip = Column(String)
    local_port = Column(String)
    foreign_ip = Column(String)
    foreign_port = Column(String)
    state = Column(String)
    pid = Column(String)
    process_name = Column(String)


class ImageHistory(Base):
    __tablename__ = "image_history"

    id = Column(Integer, primary_key=True, index=True)
    image_uuid = Column(String, index=True)
    digest = Column(String)
    age = Column(String)
    timestamp = Column(String)
    action = Column(String)
    size = Column(String)
    comment = Column(String)

class ThreatModel(Base):
    __tablename__ = "threat_model_events"

    id = Column(Integer, primary_key=True, index=True)
    image_uuid = Column(String, index=True)
    technique = Column(String, index=True)
    event = Column(String, index=True)


