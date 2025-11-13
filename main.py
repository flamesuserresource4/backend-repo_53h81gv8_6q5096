import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt
from bson import ObjectId

from database import db
from schemas import User, Project, Message

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Kick Start Visuals API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility functions

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)

# Auth dependency (manual bearer parsing)
from fastapi import Header

def get_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    return authorization.split(" ", 1)[1]

async def get_current_user(token: str = Depends(get_bearer_token)):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Schemas
class SignupModel(BaseModel):
    name: str
    email: str
    password: str
    phone: Optional[str] = None

class LoginModel(BaseModel):
    email: str
    password: str

class ProfileUpdateModel(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None

class ProjectCreateModel(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None
    selected_service: str
    description: str
    budget: Optional[str] = None

class StatusUpdateModel(BaseModel):
    status: str
    notes: Optional[str] = None

class MessageModel(BaseModel):
    project_id: str
    content: str

@app.get("/")
def root():
    return {"message": "Kick Start Visuals API running"}

@app.get("/test")
def test_database():
    from database import db as _db
    return {"db_connected": _db is not None}

# Auth endpoints
@app.post("/auth/signup")
def signup(payload: SignupModel):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = User(
        name=payload.name,
        email=payload.email,
        password_hash=hash_password(payload.password),
        phone=payload.phone,
        is_admin=False
    ).model_dump()
    inserted_id = db["user"].insert_one(user_doc).inserted_id
    token = create_access_token({"sub": str(inserted_id)})
    return {"token": token, "user": {"_id": str(inserted_id), "name": payload.name, "email": payload.email, "is_admin": False}}

@app.post("/auth/login")
def login(payload: LoginModel):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"])})
    return {"access_token": token, "token_type": "bearer", "user": {"_id": str(user["_id"]), "name": user.get("name"), "email": user.get("email"), "is_admin": user.get("is_admin", False)}}

# Customer profile
@app.get("/me")
def get_me(current_user=Depends(get_current_user)):
    u = current_user
    return {"_id": str(u["_id"]), "name": u.get("name"), "email": u.get("email"), "phone": u.get("phone"), "is_admin": u.get("is_admin", False)}

@app.put("/me")
def update_me(payload: ProfileUpdateModel, current_user=Depends(get_current_user)):
    update = {k: v for k, v in payload.model_dump().items() if v is not None}
    if update:
        db["user"].update_one({"_id": current_user["_id"]}, {"$set": update})
    u = db["user"].find_one({"_id": current_user["_id"]})
    return {"_id": str(u["_id"]), "name": u.get("name"), "email": u.get("email"), "phone": u.get("phone"), "is_admin": u.get("is_admin", False)}

# Projects
@app.post("/projects")
def create_project(payload: ProjectCreateModel, current_user=Depends(get_current_user)):
    project = Project(
        user_id=str(current_user["_id"]),
        name=payload.name,
        email=payload.email,
        phone=payload.phone,
        selected_service=payload.selected_service,
        description=payload.description,
        budget=payload.budget,
        status="Pending",
        notes=None,
        files=[]
    ).model_dump()
    inserted_id = db["project"].insert_one(project).inserted_id
    # initial message
    db["message"].insert_one({
        "project_id": str(inserted_id),
        "sender_id": str(current_user["_id"]),
        "sender_role": "customer",
        "content": "New project submitted",
        "created_at": datetime.now(timezone.utc)
    })
    return {"_id": str(inserted_id)}

@app.get("/projects")
def list_my_projects(current_user=Depends(get_current_user)):
    cur = db["project"].find({"user_id": str(current_user["_id"])})
    items = []
    for p in cur:
        p["_id"] = str(p["_id"])
        items.append(p)
    return items

@app.post("/projects/{project_id}/files")
async def upload_file(project_id: str, file: UploadFile = File(...), current_user=Depends(get_current_user)):
    project = db["project"].find_one({"_id": ObjectId(project_id), "user_id": str(current_user["_id"])})
    if not project and not current_user.get("is_admin", False):
        raise HTTPException(status_code=404, detail="Project not found")
    content = await file.read()
    file_meta = {
        "filename": file.filename,
        "content_type": file.content_type,
        "size": len(content),
        "uploaded_at": datetime.now(timezone.utc)
    }
    db["project"].update_one({"_id": ObjectId(project_id)}, {"$push": {"files": file_meta}})
    return {"message": "File uploaded", "file": file_meta}

@app.post("/projects/{project_id}/messages")
def send_message(project_id: str, payload: MessageModel, current_user=Depends(get_current_user)):
    project = db["project"].find_one({"_id": ObjectId(project_id)})
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    sender_role = "admin" if current_user.get("is_admin", False) else "customer"
    msg = Message(
        project_id=project_id,
        sender_id=str(current_user["_id"]),
        sender_role=sender_role,
        content=payload.content,
        created_at=datetime.now(timezone.utc)
    ).model_dump()
    db["message"].insert_one(msg)
    return {"message": "Sent"}

@app.get("/projects/{project_id}/messages")
def get_messages(project_id: str, current_user=Depends(get_current_user)):
    msgs = list(db["message"].find({"project_id": project_id}).sort("created_at", 1))
    for m in msgs:
        m["_id"] = str(m["_id"]) 
    return msgs

# Admin endpoints
@app.get("/admin/projects")
def admin_list_projects(service: Optional[str] = None, status: Optional[str] = None, current_user=Depends(get_current_user)):
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admins only")
    q = {}
    if service:
        q["selected_service"] = service
    if status:
        q["status"] = status
    cur = db["project"].find(q).sort("created_at", -1)
    items = []
    for p in cur:
        p["_id"] = str(p["_id"])
        items.append(p)
    return items

@app.put("/admin/projects/{project_id}/status")
def admin_update_status(project_id: str, payload: StatusUpdateModel, current_user=Depends(get_current_user)):
    if not current_user.get("is_admin", False):
        raise HTTPException(status_code=403, detail="Admins only")
    update = {"status": payload.status}
    if payload.notes is not None:
        update["notes"] = payload.notes
    db["project"].update_one({"_id": ObjectId(project_id)}, {"$set": update})
    return {"message": "Status updated"}

@app.get("/schema")
def get_schema():
    from inspect import getsource
    import schemas as s
    return {"schemas": getsource(s)}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
