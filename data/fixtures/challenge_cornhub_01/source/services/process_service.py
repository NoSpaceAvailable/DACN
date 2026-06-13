from fastapi import Form, Request, HTTPException
import mimetypes, base64, os
from pathlib import Path
from utils import filter

async def debug(request: Request):
    body = await request.body()

    return {
        "headers": dict(request.headers),
        "form_parameters": dict(await request.form()),
        "body": body.decode('utf-8', errors='ignore')
    }

def search_document(file_name: str = Form(...)):
    document_dir = "/cornhub"
    
    try:
        filter(file_name)
        normalize_name = os.path.expandvars(file_name)
        file_path = os.path.join(document_dir, normalize_name)
        with open(file_path, 'rb') as file:
            file_content = file.read()
        
        encoded_file_content = base64.b64encode(file_content).decode('utf-8')
        file_type = mimetypes.guess_type(file_path)[0]

        return {
            "content": encoded_file_content,
            "mime_type": file_type or "text/plain",
            "file_name": os.path.basename(file_path)
        }
    except Exception as e:
        return {"error": str(e)}
