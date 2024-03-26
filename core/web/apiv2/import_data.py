import json

from fastapi import APIRouter, File, UploadFile

from core.common.misp_to_yeti import MispToYeti

router = APIRouter()


@router.post("/import_misp_json", tags=["import_misp_json"])
async def import_misp_json(misp_file_json: UploadFile = File(...)):
    contents = await misp_file_json.read()
    data_json = json.loads(contents)

    converter = MispToYeti(data_json["Event"])
    converter.misp_to_yeti()
    return {"status": True}
