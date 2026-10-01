import os
import re
import subprocess
import uuid
import json
import zipfile
import io
import time
from pathlib import Path
from typing import List, Optional, Union
import bcrypt
import jwt
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request, Depends
from fastapi.responses import StreamingResponse, FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.background import BackgroundTask

SECRET_KEY = os.getenv("JWT_SECRET", "super-secret-tactics-key-change-in-prod")
ALGORITHM = "HS256"

app = FastAPI(title="Sports Film Room Analyzer")

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
CLIPS_DIR = DATA_DIR / "clips"
REELS_DIR = DATA_DIR / "reels"
DB_FILE = DATA_DIR / "store.json"

for folder in [UPLOAD_DIR, CLIPS_DIR, REELS_DIR]:
    folder.mkdir(parents=True, exist_ok=True)

security = HTTPBearer()

app.mount("/media/uploads", StaticFiles(directory=str(UPLOAD_DIR)), name="uploads")
app.mount("/media/clips", StaticFiles(directory=str(CLIPS_DIR)), name="clips")
app.mount("/media/reels", StaticFiles(directory=str(REELS_DIR)), name="reels")

def sanitize_for_filename(name: Optional[str], default: str = "Unassigned") -> str:
    if not name or not name.strip():
        return default
    clean = name.strip()
    if "unassigned" in clean.lower():
        return "Team"
    clean = clean.replace("#", "").replace("/", " ").replace("&", "")
    clean = re.sub(r'[^\w\s-]', '', clean)
    clean = re.sub(r'[\s_-]+', '_', clean).strip('_')
    return clean if clean else default

def init_db():
    if not DB_FILE.exists():
        hashed_admin = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
        hashed_coach = bcrypt.hashpw(b"coach123", bcrypt.gensalt()).decode('utf-8')
        hashed_viewer = bcrypt.hashpw(b"viewer123", bcrypt.gensalt()).decode('utf-8')
        default_data = {
            "users": [
                {"id": "usr_admin", "username": "admin", "password_hash": hashed_admin, "role": "admin", "project_ids": ["*"]},
                {"id": "usr_coach", "username": "coach", "password_hash": hashed_coach, "role": "coach", "project_ids": ["proj_varsity"]},
                {"id": "usr_viewer", "username": "viewer", "password_hash": hashed_viewer, "role": "viewer", "project_ids": ["proj_varsity"]}
            ],
            "projects": [
                {
                    "id": "proj_varsity",
                    "name": "Varsity Season Opener",
                    "sport": "Basketball",
                    "opponent": "West High Tigers",
                    "game_date": "2026-10-15",
                    "league": "Class 4A Regional",
                    "description": "Season opener game tape",
                    "video_filename": None,
                    "roster_name": "Varsity 2026"
                }
            ],
            "rosters": [
                {
                    "name": "Varsity 2026",
                    "players": ["#23 Jordan", "#33 Pippen", "#91 Rodman", "#4 Kerr", "#9 Harper"]
                },
                {
                    "name": "JV Squad",
                    "players": ["#2 Curry", "#3 Paul", "#11 Thompson", "#23 Green"]
                },
                {
                    "name": "Varsity Football",
                    "players": ["#12 Brady", "#87 Gronkowski", "#11 Edelman", "#54 Bruschi"]
                },
                {
                    "name": "Varsity Soccer",
                    "players": ["#10 Messi", "#7 Ronaldo", "#11 Neymar", "#9 Haaland"]
                }
            ],
            "clips": [],
            "reels": []
        }
        with open(DB_FILE, "w") as f:
            json.dump(default_data, f, indent=2)

init_db()

def read_db():
    try:
        with open(DB_FILE, "r") as f:
            data = json.load(f)
            data.setdefault("reels", [])
            data.setdefault("rosters", [])
            for p in data.get("projects", []):
                p.setdefault("sport", "Basketball")
            for c in data.get("clips", []):
                if "categories" not in c and "category" in c:
                    c["categories"] = [c["category"]] if c["category"] else ["General"]
                if "players" not in c:
                    c["players"] = [c["player"]] if c.get("player") else ["Unassigned / Team Play"]
                c.setdefault("sport", "Basketball")
            return data
    except Exception:
        return {"users": [], "projects": [], "clips": [], "reels": [], "rosters": []}

def write_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=2)

def create_token(user: dict) -> str:
    payload = {
        "sub": user["id"],
        "username": user["username"],
        "role": user["role"],
        "project_ids": user.get("project_ids", []),
        "player_name": user.get("player_name", None),
        "exp": int(time.time()) + (3600 * 24 * 7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Session expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def check_project_access(user: dict, project_id: str):
    if user["role"] in ["admin", "player"] or "*" in user.get("project_ids", []):
        return True
    if project_id in user.get("project_ids", []):
        return True
    raise HTTPException(status_code=403, detail="Access denied for this project")

@app.get("/", response_class=FileResponse)
async def serve_app(request: Request):
    return FileResponse(BASE_DIR / "templates" / "index.html")

# --- Auth Endpoints ---
class LoginPayload(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
def login(payload: LoginPayload):
    db = read_db()
    user = next((u for u in db["users"] if u["username"].lower() == payload.username.lower()), None)
    if not user or not bcrypt.checkpw(payload.password.encode('utf-8'), user["password_hash"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    return {
        "access_token": create_token(user),
        "token_type": "bearer",
        "user": {
            "id": user["id"], 
            "username": user["username"], 
            "role": user["role"],
            "player_name": user.get("player_name"),
            "project_ids": user.get("project_ids", [])
        }
    }

# --- User Management (Admin Only) ---
class UserCreatePayload(BaseModel):
    username: str
    password: str
    role: str
    project_ids: List[str]
    player_name: Optional[str] = None

@app.get("/api/admin/users")
def list_users(user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    db = read_db()
    return [{
        "id": u["id"],
        "username": u["username"],
        "role": u["role"],
        "player_name": u.get("player_name"),
        "project_ids": u.get("project_ids", [])
    } for u in db["users"]]

@app.post("/api/admin/users")
def create_user(payload: UserCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    if payload.role not in ["admin", "coach", "viewer", "player"]:
        raise HTTPException(status_code=400, detail="Invalid role specified")
    if payload.role == "player" and not payload.player_name:
        raise HTTPException(status_code=400, detail="Player accounts must be assigned to a player")
    if len(payload.username.strip()) < 3 or len(payload.password) < 4:
        raise HTTPException(status_code=400, detail="Username (min 3 chars) and Password (min 4 chars) required")

    db = read_db()
    if any(u["username"].lower() == payload.username.lower().strip() for u in db["users"]):
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_pw = bcrypt.hashpw(payload.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    new_user = {
        "id": f"usr_{uuid.uuid4().hex[:6]}",
        "username": payload.username.strip(),
        "password_hash": hashed_pw,
        "role": payload.role,
        "player_name": payload.player_name if payload.role == "player" else None,
        "project_ids": ["*"] if payload.role in ["admin", "player"] else payload.project_ids
    }
    db["users"].append(new_user)
    write_db(db)
    return {"status": "created", "id": new_user["id"]}

@app.delete("/api/admin/users/{user_id}")
def delete_user(user_id: str, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    if user["sub"] == user_id:
        raise HTTPException(status_code=400, detail="Cannot delete your own active admin account")
    
    db = read_db()
    target = next((u for u in db["users"] if u["id"] == user_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    
    db["users"] = [u for u in db["users"] if u["id"] != user_id]
    write_db(db)
    return {"status": "deleted"}

# --- Project Management Endpoints ---
class ProjectCreatePayload(BaseModel):
    name: str
    sport: Optional[str] = "Basketball"
    opponent: Optional[str] = ""
    game_date: Optional[str] = ""
    league: Optional[str] = ""
    description: Optional[str] = ""
    roster_name: Optional[str] = "Varsity 2026"

class ProjectUpdatePayload(BaseModel):
    name: str
    sport: Optional[str] = "Basketball"
    opponent: Optional[str] = ""
    game_date: Optional[str] = ""
    league: Optional[str] = ""
    description: Optional[str] = ""
    roster_name: Optional[str] = "Varsity 2026"

@app.get("/api/projects")
def get_projects(user: dict = Depends(get_current_user)):
    db = read_db()
    if user["role"] in ["admin", "player"] or "*" in user.get("project_ids", []):
        return db["projects"]
    return [p for p in db["projects"] if p["id"] in user.get("project_ids", [])]

@app.post("/api/projects")
def create_project(payload: ProjectCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only Admins can create new game projects")
    db = read_db()
    new_project = {
        "id": f"proj_{uuid.uuid4().hex[:6]}",
        "name": payload.name,
        "sport": payload.sport or "Basketball",
        "opponent": payload.opponent,
        "game_date": payload.game_date,
        "league": payload.league,
        "description": payload.description,
        "roster_name": payload.roster_name,
        "video_filename": None
    }
    db["projects"].append(new_project)
    write_db(db)
    return new_project

@app.put("/api/projects/{project_id}")
def update_project(project_id: str, payload: ProjectUpdatePayload, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to edit projects")
    
    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    project["name"] = payload.name
    project["sport"] = payload.sport or project.get("sport", "Basketball")
    project["opponent"] = payload.opponent
    project["game_date"] = payload.game_date
    project["league"] = payload.league
    project["description"] = payload.description
    project["roster_name"] = payload.roster_name

    write_db(db)
    return project

@app.delete("/api/projects/{project_id}")
def delete_project(project_id: str, user: dict = Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only Admins can delete game projects")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    if project.get("video_filename"):
        raw_video_path = UPLOAD_DIR / project["video_filename"]
        if raw_video_path.exists():
            try:
                raw_video_path.unlink()
            except Exception:
                pass

    clips_to_remove = [c for c in db["clips"] if c.get("project_id") == project_id]
    for c in clips_to_remove:
        clip_path = CLIPS_DIR / c["filename"]
        if clip_path.exists():
            try:
                clip_path.unlink()
            except Exception:
                pass

    db["clips"] = [c for c in db["clips"] if c.get("project_id") != project_id]
    db["projects"] = [p for p in db["projects"] if p["id"] != project_id]

    for u in db["users"]:
        if "project_ids" in u and project_id in u["project_ids"]:
            u["project_ids"] = [pid for pid in u["project_ids"] if pid != project_id]

    write_db(db)
    return {"status": "deleted", "project_id": project_id}

# --- Rosters Management ---
class RosterSavePayload(BaseModel):
    name: str
    players: List[str]
    old_name: Optional[str] = None

@app.get("/api/rosters")
def list_rosters(user: dict = Depends(get_current_user)):
    db = read_db()
    return db.get("rosters", [])

@app.post("/api/rosters")
def save_roster(payload: RosterSavePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to edit rosters")

    db = read_db()
    rosters = db.setdefault("rosters", [])
    
    clean_players = [
        p.strip() for p in payload.players 
        if p.strip() and "unassigned" not in p.lower()
    ]

    target_name = payload.old_name if payload.old_name else payload.name.strip()
    existing = next((r for r in rosters if r["name"].lower() == target_name.lower()), None)
    
    if existing:
        existing["name"] = payload.name.strip()
        existing["players"] = clean_players
        if payload.old_name and payload.old_name != payload.name.strip():
            for p in db.get("projects", []):
                if p.get("roster_name") == payload.old_name:
                    p["roster_name"] = payload.name.strip()
    else:
        rosters.append({"name": payload.name.strip(), "players": clean_players})

    write_db(db)
    return {"status": "saved", "rosters": rosters}

@app.delete("/api/rosters/{roster_name}")
def delete_roster(roster_name: str, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to delete rosters")

    db = read_db()
    rosters = db.get("rosters", [])
    if len(rosters) <= 1:
        raise HTTPException(status_code=400, detail="Must keep at least one roster")

    db["rosters"] = [r for r in rosters if r["name"].lower() != roster_name.lower()]
    write_db(db)
    return {"status": "deleted"}

# --- Resilient Chunked Video Ingestion with Fast-Start Relocation ---
@app.post("/api/projects/{project_id}/upload-chunk")
async def upload_video_chunk(
    project_id: str,
    chunk: UploadFile = File(...),
    chunk_index: int = Form(...),
    total_chunks: int = Form(...),
    original_filename: str = Form(...),
    upload_id: str = Form(...),
    user: dict = Depends(get_current_user)
):
    check_project_access(user, project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to upload video")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    ext = Path(original_filename).suffix or ".mp4"
    safe_filename = f"{project_id}_{upload_id}{ext}"
    target_path = UPLOAD_DIR / safe_filename

    mode = "wb" if chunk_index == 0 else "ab"
    with open(target_path, mode) as f:
        while content := await chunk.read(1024 * 1024 * 4):
            f.write(content)

    if chunk_index == total_chunks - 1:
        faststart_path = UPLOAD_DIR / f"faststart_{safe_filename}"
        cmd_optimize = [
            "ffmpeg", "-y",
            "-i", str(target_path),
            "-c", "copy",
            "-movflags", "+faststart",
            str(faststart_path)
        ]
        res_opt = subprocess.run(cmd_optimize, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        if res_opt.returncode == 0 and faststart_path.exists() and faststart_path.stat().st_size > 0:
            target_path.unlink(missing_ok=True)
            faststart_path.rename(target_path)
        else:
            if faststart_path.exists():
                faststart_path.unlink(missing_ok=True)

        project["video_filename"] = safe_filename
        project["video_original_name"] = original_filename
        write_db(db)
        return {
            "status": "complete",
            "filename": safe_filename,
            "url": f"/media/uploads/{safe_filename}"
        }

    return {"status": "chunk_received", "chunk_index": chunk_index}

# --- Video Clipping & Editing Endpoints ---
class ClipCreatePayload(BaseModel):
    project_id: str
    start_time: float
    end_time: float
    categories: Optional[List[str]] = []
    category: Optional[str] = None
    players: Optional[List[str]] = []
    player: Optional[str] = None
    notes: Optional[str] = ""

class ClipUpdatePayload(BaseModel):
    categories: List[str]
    players: List[str]
    notes: Optional[str] = ""

@app.post("/api/clips")
def create_clip(payload: ClipCreatePayload, user: dict = Depends(get_current_user)):
    check_project_access(user, payload.project_id)
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to slice clips")

    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == payload.project_id), None)
    if not project or not project.get("video_filename"):
        raise HTTPException(status_code=400, detail="Source game tape not uploaded")

    input_path = UPLOAD_DIR / project["video_filename"]
    if payload.end_time <= payload.start_time:
        raise HTTPException(status_code=400, detail="Out point must be greater than In point")

    tags = payload.categories or []
    if payload.category and payload.category not in tags:
        tags.insert(0, payload.category)
    if not tags:
        tags = ["Play"]

    tagged_players = payload.players or []
    if payload.player and payload.player not in tagged_players:
        tagged_players.insert(0, payload.player)
    if not tagged_players:
        tagged_players = ["Unassigned / Team Play"]

    clip_id = uuid.uuid4().hex[:8]
    clean_player_slug = "_".join([sanitize_for_filename(p, default="Player") for p in tagged_players[:2]])
    tags_slug = "_".join([sanitize_for_filename(t, default="Tag") for t in tags[:2]])
    clip_filename = f"clip_{clean_player_slug}_{tags_slug}_{clip_id}.mp4"
    output_path = CLIPS_DIR / clip_filename
    duration = payload.end_time - payload.start_time

    cmd_fast = [
        "ffmpeg", "-y",
        "-ss", str(payload.start_time),
        "-i", str(input_path),
        "-t", str(duration),
        "-c", "copy",
        "-map", "0:v:0",
        "-map", "0:a:0?",
        "-avoid_negative_ts", "make_zero",
        "-movflags", "+faststart",
        str(output_path)
    ]
    res = subprocess.run(cmd_fast, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=15)

    if res.returncode != 0 or not output_path.exists() or output_path.stat().st_size < 1000:
        cmd_fallback = [
            "ffmpeg", "-y",
            "-ss", str(payload.start_time),
            "-i", str(input_path),
            "-t", str(duration),
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-crf", "26",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-b:a", "96k",
            "-threads", "0",
            "-movflags", "+faststart",
            str(output_path)
        ]
        res_fb = subprocess.run(cmd_fallback, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=30)
        if res_fb.returncode != 0:
            raise HTTPException(status_code=500, detail="Clip processing failed")

    clip_record = {
        "id": clip_id,
        "project_id": payload.project_id,
        "project_name": project["name"],
        "sport": project.get("sport", "Basketball"),
        "filename": clip_filename,
        "url": f"/media/clips/{clip_filename}",
        "categories": tags,
        "category": tags[0],
        "players": tagged_players,
        "player": tagged_players[0],
        "notes": payload.notes or "",
        "start_time": round(payload.start_time, 2),
        "end_time": round(payload.end_time, 2),
        "duration": round(duration, 2),
        "created_by": user["username"]
    }
    db["clips"].insert(0, clip_record)
    write_db(db)
    return clip_record

@app.put("/api/clips/{clip_id}")
def update_clip(clip_id: str, payload: ClipUpdatePayload, user: dict = Depends(get_current_user)):
    db = read_db()
    clip = next((c for c in db["clips"] if c["id"] == clip_id), None)
    if not clip:
        raise HTTPException(status_code=404, detail="Clip not found")

    check_project_access(user, clip["project_id"])
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to edit clips")

    tags = [t.strip() for t in payload.categories if t.strip()]
    if not tags:
        tags = ["Play"]

    pls = [p.strip() for p in payload.players if p.strip()]
    if not pls:
        pls = ["Unassigned / Team Play"]

    clip["categories"] = tags
    clip["category"] = tags[0]
    clip["players"] = pls
    clip["player"] = pls[0]
    clip["notes"] = payload.notes or ""

    write_db(db)
    return clip

@app.get("/api/projects/{project_id}/clips")
def get_project_clips(project_id: str, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    db = read_db()
    return [c for c in db["clips"] if c["project_id"] == project_id]

@app.delete("/api/clips/{clip_id}")
def delete_clip(clip_id: str, user: dict = Depends(get_current_user)):
    db = read_db()
    clip = next((c for c in db["clips"] if c["id"] == clip_id), None)
    if not clip:
        raise HTTPException(status_code=404, detail="Clip not found")

    check_project_access(user, clip["project_id"])
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to delete clips")

    clip_path = CLIPS_DIR / clip["filename"]
    if clip_path.exists():
        clip_path.unlink()
        
    db["clips"] = [c for c in db["clips"] if c["id"] != clip_id]
    
    for r in db["reels"]:
        r["clip_ids"] = [cid for cid in r.get("clip_ids", []) if cid != clip_id]

    write_db(db)
    return {"status": "deleted"}

# --- Player Vault Query Endpoint ---
@app.get("/api/players/clips")
def get_player_clips(
    player_name: Optional[str] = None, 
    roster_name: Optional[str] = None, 
    user: dict = Depends(get_current_user)
):
    db = read_db()
    
    if user["role"] == "player":
        target_player = user.get("player_name")
        if not target_player:
            raise HTTPException(status_code=403, detail="No player linked to this account")
    else:
        target_player = player_name

    if not target_player:
        return []

    allowed_proj_ids = None
    if user["role"] not in ["admin", "player"] and "*" not in user.get("project_ids", []):
        allowed_proj_ids = set(user.get("project_ids", []))

    matching_project_ids = None
    if roster_name and roster_name != "ALL":
        matching_project_ids = {
            p["id"] for p in db.get("projects", []) 
            if p.get("roster_name", "").lower() == roster_name.lower()
        }

    matched_clips = []
    target_clean = target_player.strip().lower()

    for clip in db.get("clips", []):
        if allowed_proj_ids is not None and clip.get("project_id") not in allowed_proj_ids:
            continue
        if matching_project_ids is not None and clip.get("project_id") not in matching_project_ids:
            continue

        clip_players = [p.strip().lower() for p in clip.get("players", [clip.get("player", "")])]
        if target_clean in clip_players:
            matched_clips.append(clip)

    return matched_clips

# --- Custom Reels & Playlists ---
class ReelCreatePayload(BaseModel):
    title: str
    description: Optional[str] = ""

class ReelUpdateClipsPayload(BaseModel):
    clip_ids: List[str]

@app.get("/api/reels")
def list_reels(user: dict = Depends(get_current_user)):
    db = read_db()
    return db.get("reels", [])

@app.post("/api/reels")
def create_reel(payload: ReelCreatePayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to create reels")
    db = read_db()
    new_reel = {
        "id": f"reel_{uuid.uuid4().hex[:8]}",
        "title": payload.title.strip(),
        "description": payload.description.strip(),
        "clip_ids": [],
        "created_by": user["username"],
        "created_at": int(time.time())
    }
    db["reels"].append(new_reel)
    write_db(db)
    return new_reel

@app.get("/api/reels/{reel_id}")
def get_reel(reel_id: str, user: dict = Depends(get_current_user)):
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    
    clips_lookup = {c["id"]: c for c in db["clips"]}
    ordered_clips = [clips_lookup[cid] for cid in reel.get("clip_ids", []) if cid in clips_lookup]
    return {
        "reel": reel,
        "clips": ordered_clips
    }

@app.put("/api/reels/{reel_id}/clips")
def update_reel_clips(reel_id: str, payload: ReelUpdateClipsPayload, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to modify reels")
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    
    reel["clip_ids"] = payload.clip_ids
    write_db(db)
    return reel

@app.post("/api/reels/{reel_id}/add-clip")
def add_clip_to_reel(reel_id: str, clip_id: str = Form(...), user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to modify reels")
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")
    
    if clip_id not in reel.get("clip_ids", []):
        reel.setdefault("clip_ids", []).append(clip_id)
        write_db(db)
    return reel

@app.delete("/api/reels/{reel_id}")
def delete_reel(reel_id: str, user: dict = Depends(get_current_user)):
    if user["role"] in ["viewer", "player"]:
        raise HTTPException(status_code=403, detail="Permission denied to delete reels")
    db = read_db()
    db["reels"] = [r for r in db["reels"] if r["id"] != reel_id]
    write_db(db)
    return {"status": "deleted"}

def cleanup_temp_files(*paths: Path):
    for p in paths:
        if p.exists():
            try:
                p.unlink()
            except Exception:
                pass

# --- Highlight Reel Concatenation Export ---
@app.get("/api/reels/{reel_id}/export-video")
def export_reel_concatenated_video(reel_id: str, user: dict = Depends(get_current_user)):
    db = read_db()
    reel = next((r for r in db["reels"] if r["id"] == reel_id), None)
    if not reel:
        raise HTTPException(status_code=404, detail="Reel not found")

    clips_lookup = {c["id"]: c for c in db["clips"]}
    ordered_clips = [clips_lookup[cid] for cid in reel.get("clip_ids", []) if cid in clips_lookup]

    valid_clip_paths = []
    for c in ordered_clips:
        p = CLIPS_DIR / c["filename"]
        if p.exists() and p.stat().st_size > 0:
            valid_clip_paths.append(p)

    if not valid_clip_paths:
        raise HTTPException(status_code=400, detail="No valid MP4 clips found in this reel to concatenate")

    export_id = uuid.uuid4().hex[:8]
    concat_list_file = REELS_DIR / f"concat_{export_id}.txt"
    output_video_path = REELS_DIR / f"reel_{export_id}.mp4"

    with open(concat_list_file, "w") as f:
        for p in valid_clip_paths:
            clean_path = str(p.resolve()).replace("'", "'\\''")
            f.write(f"file '{clean_path}'\n")

    cmd = [
        "ffmpeg", "-y",
        "-f", "concat",
        "-safe", "0",
        "-i", str(concat_list_file),
        "-c", "copy",
        "-movflags", "+faststart",
        str(output_video_path)
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if res.returncode != 0 or not output_video_path.exists() or output_video_path.stat().st_size == 0:
        cmd_reencode = [
            "ffmpeg", "-y",
            "-f", "concat",
            "-safe", "0",
            "-i", str(concat_list_file),
            "-vf", "scale=1920:1080:force_original_aspect_ratio=decrease,pad=1920:1080:(ow-iw)/2:(oh-ih)/2,setsar=1",
            "-c:v", "libx264",
            "-preset", "veryfast",
            "-crf", "23",
            "-pix_fmt", "yuv420p",
            "-c:a", "aac",
            "-b:a", "128k",
            "-ac", "2",
            "-ar", "44100",
            "-movflags", "+faststart",
            str(output_video_path)
        ]
        res_re = subprocess.run(cmd_reencode, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res_re.returncode != 0:
            cleanup_temp_files(concat_list_file, output_video_path)
            err_msg = res_re.stderr.decode("utf-8", errors="ignore")
            raise HTTPException(status_code=500, detail=f"Highlight stitching failed: {err_msg[-200:]}")

    if concat_list_file.exists():
        try:
            concat_list_file.unlink()
        except Exception:
            pass

    download_name = f"{sanitize_for_filename(reel['title'], default='Highlight_Reel')}.mp4"
    return FileResponse(
        path=str(output_video_path),
        media_type="application/octet-stream",
        filename=download_name,
        headers={
            "Content-Disposition": f'attachment; filename="{download_name}"',
            "Accept-Ranges": "none"
        },
        background=BackgroundTask(cleanup_temp_files, output_video_path)
    )

@app.get("/api/projects/{project_id}/export-zip")
def export_project_clips_zip(project_id: str, category: Optional[str] = None, user: dict = Depends(get_current_user)):
    check_project_access(user, project_id)
    db = read_db()
    project = next((p for p in db["projects"] if p["id"] == project_id), None)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")

    clips = [c for c in db["clips"] if c["project_id"] == project_id]
    if category and category != "ALL":
        clips = [c for c in clips if category in c.get("categories", [c.get("category", "")])]

    if not clips:
        raise HTTPException(status_code=400, detail="No clips available to export")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr("metadata.json", json.dumps(clips, indent=2))
        csv_header = "ID,Sport,Categories,Players,Filename,Start_Sec,End_Sec,Duration_Sec,Created_By\n"
        
        csv_rows = []
        for c in clips:
            cats = ";".join(c.get("categories", [c.get("category", "")]))
            pls = ";".join(c.get("players", [c.get("player", "")]))
            sp = c.get("sport", "Basketball")
            csv_rows.append(
                f'{c["id"]},{sp},"{cats}","{pls}",{c["filename"]},{c["start_time"]},{c["end_time"]},{c["duration"]},{c["created_by"]}'
            )
        zip_file.writestr("summary.csv", csv_header + "\n".join(csv_rows))

        for c in clips:
            file_path = CLIPS_DIR / c["filename"]
            if file_path.exists():
                zip_file.write(file_path, arcname=f"clips/{c['filename']}")

    zip_buffer.seek(0)
    zip_filename = f"{project['name'].replace(' ', '_')}_clips.zip"
    
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{zip_filename}"'}
    )