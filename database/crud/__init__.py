import re 
import subprocess

import docker

from time import sleep

from fastapi import Depends

from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError

import database 
import database.models as models
import database.schema as schema
from database.crud.threat_intel import MitreScan as threat_scanner

def get_scan_status(image_uuid: str, db: Session=Depends(database.get_db)) -> bool:
    if db.query(models.ScanResults).filter(models.ScanResults.image_uuid == image_uuid).first():
        return 'scanned'
    elif db.query(models.ScanQueue).filter(models.ScanQueue.image_uuid == image_uuid).first():
        return 'in queue, awaiting scan'
    else:
        return 'not scanned'


def create_scan(image: schema.ImageScanModel, image_uuid: str, db: Session=Depends(database.get_db)) -> bool:
    scan = database.models.ScanQueue(image_uuid=image_uuid, 
                                     image_name=image.image_name, 
                                     image_tag=image.image_tag
    )

    db.add(scan)
    db.commit()

    return start_scan(image, image_uuid, db)


def get_image_data(image_uuid: str, db: Session=Depends(database.get_db)):
    image = db.query(models.ScanResults).filter(models.ScanResults.image_uuid == image_uuid).first()
    if not image: 
        return False
    
    return {
        'meta': {
            'image_name': image.image_name,
            'image_tag': image.image_tag,
            'image_uuid': image.image_uuid,
            'image_alerts': image.image_alerts
        },
        'running_processes': get_running_processes(image_uuid, db),
        'network_connections': get_network_connections(image_uuid, db),
        'image_history': get_image_history(image_uuid, db)
    }


def start_scan(image: schema.ImageScanModel, image_uuid: str, db: Session=Depends(database.get_db)) -> None:
    client = docker.from_env()
    image_path = ':'.join([image.image_name, image.image_tag]) if image.image_tag else image.image_name
    try:
        container = client.containers.run(image_path, detach=True)
    except docker.errors.ImageNotFound:
        return False

    if not set_running_processes(container, image_uuid, db):
        container = client.containers.run(image_path, 'sleep 500', detach=True)
    
    set_network_connections(container, image_uuid, db)
    set_image_history(image_path, image_uuid, db)
    threat_scanner(container, image_path, image_uuid, db)
    cleanup_from_scan(container)
    complete_scan(image, image_uuid, db)
    return True

def cleanup_from_scan(container) -> None:
    container.remove(v=True, force=True)

def complete_scan(image: schema.ImageScanModel, image_uuid: str, db: Session=Depends(database.get_db)) -> None:
    try:
        db.add(models.ScanResults( 
            image_uuid = image_uuid,     
            image_name = image.image_name,
            image_tag = image.image_tag,
            image_alerts = []
        ))
        db.commit()
    except IntegrityError:
        db.flush()
        db.rollback()
    
    scan_result = db.query(models.ScanQueue).filter(models.ScanQueue.image_uuid == image_uuid).first()

    try:
        db.delete(scan_result)
        db.commit()
    except IntegrityError:
        db.flush()
        db.rollback()

def get_all_image_data(db: Session=Depends(database.get_db)) -> dict:
    return {
        'running_processes': get_all_running_processes(db),
        'network_connections': get_all_network_connections(db),
        'image_history': get_all_image_history(db)
    }

def get_all_running_processes(db: Session=Depends(database.get_db)) -> list:
    return [row for row in db.query(models.ImageRunningProcesses).all()]

def get_all_network_connections(db: Session=Depends(database.get_db)) -> list:
    return [row for row in db.query(models.ImageNetworkConnections).all()]

def get_all_image_history(db: Session=Depends(database.get_db)) -> list:
    return [row for row in db.query(models.ImageHistory).all()]

def get_running_processes(image_uuid: str, db: Session=Depends(database.get_db)) -> list:
    return [row for row in db.query(models.ImageRunningProcesses).filter(models.ImageRunningProcesses.image_uuid == image_uuid).all()]

def get_network_connections(image_uuid: str, db: Session=Depends(database.get_db)) -> list:
    return [row for row in db.query(models.ImageNetworkConnections).filter(models.ImageNetworkConnections.image_uuid == image_uuid).all()]

def get_image_history(image_uuid: str, db: Session=Depends(database.get_db)) -> list:
    return [row for row in db.query(models.ImageHistory).filter(models.ImageHistory.image_uuid == image_uuid).all()]

def set_running_processes(container, image_uuid: str, db: Session=Depends(database.get_db)) -> bool:
    try:
        results = container.exec_run(cmd="ps -ef", demux=True, privileged=True, tty=True)
    except docker.errors.APIError as e:
        print(e)
        sleep(1)
        return False

    if results.exit_code != 0:
        return True
    
    for row in results.output[0].decode('utf-8').split('\r\n')[1:-2]:
        parsed_row = re.findall('.*?(\d+).*?(\w+).*?([0-9:]+).*?(.*)', row)
        if not parsed_row or len(parsed_row[0]) != 4 or re.search('sleep 500', parsed_row[0][3]):
            continue

        if db.query(models.ImageRunningProcesses).filter(models.ImageRunningProcesses.image_uuid == image_uuid).first():
            # drop all rows where this matches
            pass
        
        try:
            db.add(models.ImageRunningProcesses( 
                image_uuid = image_uuid,      
                pid = parsed_row[0][0],
                user = parsed_row[0][1],
                time = parsed_row[0][2],
                command = parsed_row[0][3]
            ))
            db.commit()
        except IntegrityError:
            db.flush()
            db.rollback()
        
    return True


def set_network_connections(container, image_uuid: str, db: Session=Depends(database.get_db)) -> None:
    results = container.exec_run(cmd="netstat -anp | grep ':'", demux=True, privileged=True, tty=True)
    if results.exit_code != 0:
        return
    
    for row in results.output[0].decode('utf-8').split('\r\n')[2:]:
        parsed_row = re.findall('(\w+).*?(\d+).*?(\d+).*?([a-zA-Z0-9.:]+):([0-9*]+).*?([a-zA-Z0-9.:]+):([0-0*]+).*?(\w+).*?(\w+)/(.*)', row)
        if not parsed_row or len(parsed_row[0]) != 10:
            continue
        

        if db.query(models.ImageNetworkConnections).filter(models.ImageNetworkConnections.image_uuid == image_uuid).first():
            # drop all rows where this matches
            pass
        
        try:
            db.add(models.ImageNetworkConnections( 
                image_uuid = image_uuid,      
                protocol = parsed_row[0][0],
                recv_q = parsed_row[0][1],
                send_q = parsed_row[0][2],
                local_ip = parsed_row[0][3],
                local_port = parsed_row[0][4],
                foreign_ip = parsed_row[0][5],
                foreign_port = parsed_row[0][6],
                state = parsed_row[0][7],
                pid = parsed_row[0][8],
                process_name = parsed_row[0][9]
            ))
            db.commit()
        except IntegrityError:
            db.flush()
            db.rollback()


def set_image_history(image: str, image_uuid: str, db: Session=Depends(database.get_db)) -> None:
    results = subprocess.check_output([
        'docker', 
        'history', 
        image, 
        '--format', 
        '"{{.ID}}|{{.CreatedSince}}|{{.CreatedAt}}|{{.CreatedBy}}|{{.Size}}|{{.Comment}}"', 
        '--no-trunc'
    ]).decode('utf-8').split('\n')

    for row in results:
        if db.query(models.ImageHistory).filter(models.ImageHistory.image_uuid == image_uuid).first():
            # drop all rows where this matches
            pass
        
        parsed_row = row.split('|')
        if len(parsed_row) != 6:
            continue

        try:
            db.add(models.ImageHistory( 
                image_uuid = image_uuid,
                digest = parsed_row[0].lstrip('"'),
                age = parsed_row[1],
                timestamp = parsed_row[2],
                action = parsed_row[3],
                size = parsed_row[4],
                comment = parsed_row[5].rstrip('"')
            ))
            db.commit()
        except IntegrityError:
            db.flush()
            db.rollback()

