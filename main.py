import hashlib
import re

import uvicorn

from fastapi import Depends, FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session

import database

import database.crud as crud
import database.schema as schema
import database.models as models

database.Base.metadata.create_all(bind=database.engine)

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("search.html", {"request": request})

@app.get("/image/search", response_class=HTMLResponse)
async def get_image_web_search(request: Request):
    return templates.TemplateResponse("search-image.html", {"request": request})

@app.get("/image", response_class=HTMLResponse)
async def get_image_web(image_name: str, request: Request, db: Session=Depends(database.get_db)):
    results = get_image(image_name, db)
    if results:
        return templates.TemplateResponse("image.html", {'request': request, 'data': results } )
    else:
        raise HTTPException(status_code=404, detail="Image UUID not found")

@app.get("/search", response_class=HTMLResponse)
async def search(request: Request, db: Session=Depends(database.get_db)):
    return templates.TemplateResponse("search.html", {'request': request, 'data': crud.get_all_image_data(db) } )

@app.get("/api/v1/image/<image_name>", response_model=schema.ImageResultsModel)
def get_image(image_name: str, db: Session=Depends(database.get_db)):
    image_uuid = hashlib.sha1(image_name.encode('utf-8')).hexdigest()
    data = crud.get_image_data(image_uuid, db)
    if data:   
        return data

    image_information = image_name.split('|')
    image = schema.ImageScanModel(image_name=image_information[0], image_tag=image_information[1] if len(image_information) > 1 else '')
    scan(image, db)

    data = crud.get_image_data(image_uuid, db)
    if data:
        return data

@app.post("/check_image", response_model=schema.ScanStatusResponseModel)
def scan(image: schema.ImageScanModel, db: Session=Depends(database.get_db)):
    image_uuid = hashlib.sha1('|'.join([image.image_name, image.image_tag]).encode('utf-8')).hexdigest()

    status = crud.get_scan_status(image_uuid, db)
    if status == 'not scanned':
        success = crud.create_scan(image, image_uuid, db)

    return {
        'image_uuid': image_uuid,
        'image_tag': image.image_tag,
        'image_name': image.image_name,
        'status': status if status == 'not scanned' and success else 'failed to scan'
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)