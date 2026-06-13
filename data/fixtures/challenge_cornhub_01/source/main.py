from fastapi import FastAPI, Request, Depends, Form, Cookie
from db import init_db
from services.auth_service import login, update_password, forgot_password
from services.process_service import search_document, debug
from utils import verify_token, log_request


app = FastAPI()

@app.on_event("startup")
def startup():
    init_db()

@app.post("/auth/login")
def auth_login(username: str = Form(...), password: str = Form(...)):
    return login(username, password)

# Internal Only
@app.post("/auth/update_password")
def auth_update_password(username: str = Form(...), token: str = Form(...), new_password: str = Form(...)):
    return update_password(username, token, new_password)

# Internal Only
@app.post("/auth/forgot_password")
def auth_forgot_password(email: str = Form(...)):
    return forgot_password(email)

# Admin Only
@app.post("/process/debug")
async def process_debug(request: Request, session_id: str = Cookie(None), auth=Depends(verify_token)):
    result = await debug(request)
    if session_id:
        log_request(session_id, request.url.path, result)
    return result

# Admin Only
@app.post("/process/documents")
def process_document(request: Request, file_name: str = Form(...), session_id: str = Cookie(None), auth=Depends(verify_token)):
    result = search_document(file_name)
    if session_id:
        log_request(session_id, request.url.path, result)
    return result

