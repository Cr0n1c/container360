from typing import List 

from pydantic import BaseModel


class ImageScanModel(BaseModel):
    image_name: str
    image_tag: str
    

class ScanStatusResponseModel(ImageScanModel):
    image_uuid: str
    status: str

    class Config:
        orm_mode = True

class ImageMetricModel(BaseModel):
    image_uuid: str

class ImageRunningProcess(ImageMetricModel):
    pid: str
    time: str
    user: str
    command: str
    id: int

class ImageNetworkConnection(ImageMetricModel):
    protocol: str
    send_q: str
    recv_q: str
    local_ip: str
    local_port: str
    foreign_ip: str
    foreign_port: str
    state: str
    process_name: str

class ImageHistoryEntry(ImageMetricModel):
    age: str
    digest: str
    action: str
    comment: str
    timestamp: str
    size: str

class ImageResultsModel(BaseModel):
    meta: dict
    network_connections: list
    image_history: list
    running_processes: list

    class Config:
        orm_mode = True
