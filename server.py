from fastapi import FastAPI, APIRouter, HTTPException, Request, Form, Depends
from fastapi.responses import FileResponse, Response, HTMLResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict
from datetime import datetime, timezone, timedelta
import hashlib
import json
import httpx
import secrets
import jwt
import re

ROOT_DIR = Path(__file__).parent
FRONTEND_PUBLIC_DIR = ROOT_DIR.parent / 'frontend' / 'public'
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'myguyai')]

# Constants
RATE_LIMIT_REQUESTS = 50  # Per hour for tools
RATE_LIMIT_WINDOW = 3600

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable must be set")
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_HOURS = 24

# Legacy Admin credentials (kept for backward compatibility)
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'myguyai2024')

# ===========================================
# AD CONFIGURATION - Easy to update
# ===========================================
ADSENSE_PUBLISHER_ID = 'pub-9272525041915647'
ADS_TXT_CONTENT = f'google.com, {ADSENSE_PUBLISHER_ID}, DIRECT, f08c47fec0942fa0'

# ===========================================
# CLOUDFLARE TURNSTILE CONFIGURATION
# ===========================================
TURNSTILE_SECRET_KEY = os.environ.get('TURNSTILE_SECRET_KEY', '')
TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify'
TURNSTILE_ENABLED = bool(TURNSTILE_SECRET_KEY)

# ===========================================
# ROLE-BASED CMS CONFIGURATION
# ===========================================
ROLES = {
    'super_admin': {
        'name': 'Super Admin',
        'permissions': ['all']
    },
    'admin': {
        'name': 'Admin', 
        'permissions': ['manage_tools', 'manage_categories', 'manage_flash', 'view_analytics']
    },
    'seo_manager': {
        'name': 'SEO Manager',
        'permissions': ['edit_seo', 'edit_meta', 'manage_sitemap']
    },
    'editor': {
        'name': 'Editor',
        'permissions': ['edit_content', 'edit_faqs', 'create_faqs']
    }
}

# Create the main app
app = FastAPI(title="MyGuyAI Tools API")
api_router = APIRouter(prefix="/api")
security = HTTPBearer(auto_error=False)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class AdminLoginRequest(BaseModel):
    password: str

class ToolConfig(BaseModel):
    id: str
    name: str
    slug: str
    category: str
    description: str
    seo_title: str
    seo_description: str
    content: Optional[str] = None
    faqs: Optional[List[Dict]] = None
    related_tools: Optional[List[str]] = None
    enabled: bool = True

class CategoryConfig(BaseModel):
    id: str
    name: str
    slug: str
    description: str
    seo_title: str
    seo_description: str
    seo_content: Optional[str] = None

class FlashMessage(BaseModel):
    enabled: bool = False
    message: str = ""
    link: Optional[str] = None
    link_text: Optional[str] = None

class SiteSettings(BaseModel):
    flash_message: Optional[FlashMessage] = None
    homepage_title: Optional[str] = None
    homepage_description: Optional[str] = None

# ===========================================
# CMS USER MODELS
# ===========================================

class CMSUser(BaseModel):
    email: str
    name: str
    role: str  # super_admin, admin, seo_manager, editor
    active: bool = True

class CMSUserCreate(BaseModel):
    email: str
    name: str
    password: str
    role: str = 'editor'

class CMSUserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    active: Optional[bool] = None
    password: Optional[str] = None

class CMSLoginRequest(BaseModel):
    email: str
    password: str

class CMSLoginResponse(BaseModel):
    token: str
    user: Dict

class ContentUpdate(BaseModel):
    tool_id: str
    field: str  # 'seo_title', 'seo_description', 'description', 'content'
    value: str

class FAQItem(BaseModel):
    question: str
    answer: str

class FAQUpdate(BaseModel):
    tool_id: str
    faqs: List[FAQItem]

# ===========================================
# AUTHENTICATION HELPERS
# ===========================================

def hash_password(password: str) -> str:
    """Hash password using SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_jwt_token(user_data: dict) -> str:
    """Create JWT token for authenticated user"""
    payload = {
        'email': user_data['email'],
        'role': user_data['role'],
        'name': user_data['name'],
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def verify_jwt_token(token: str) -> Optional[dict]:
    """Verify and decode JWT token"""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """Get current authenticated user from JWT token"""
    if not credentials:
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = credentials.credentials
    user_data = verify_jwt_token(token)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    
    return user_data

def check_permission(user: dict, required_permission: str) -> bool:
    """Check if user has required permission"""
    role = user.get('role', '')
    if role == 'super_admin':
        return True
    
    role_config = ROLES.get(role, {})
    permissions = role_config.get('permissions', [])
    
    return required_permission in permissions or 'all' in permissions

class TurnstileVerifyRequest(BaseModel):
    token: str

class TurnstileVerifyResponse(BaseModel):
    success: bool
    message: str = ""

# ==================== TURNSTILE VERIFICATION ====================

async def verify_turnstile_token(token: str, ip: Optional[str] = None) -> bool:
    """Verify Cloudflare Turnstile token"""
    if not TURNSTILE_ENABLED:
        return True
    
    if not token or token == 'turnstile-disabled':
        return not TURNSTILE_ENABLED
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                TURNSTILE_VERIFY_URL,
                data={
                    'secret': TURNSTILE_SECRET_KEY,
                    'response': token,
                    'remoteip': ip
                },
                timeout=10.0
            )
            result = response.json()
            return result.get('success', False)
    except Exception as e:
        logger.error(f"Turnstile verification error: {e}")
        # On error, allow through to not block legitimate users
        return True

# ==================== RATE LIMITING ====================

async def check_rate_limit(request: Request, limit: int = RATE_LIMIT_REQUESTS) -> bool:
    client_ip = request.client.host if request.client else "unknown"
    key = f"rate_limit:{client_ip}"
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=RATE_LIMIT_WINDOW)
    
    count = await db.rate_limits.count_documents({
        "key": key,
        "timestamp": {"$gte": window_start}
    })
    
    if count >= limit:
        return False
    
    await db.rate_limits.insert_one({"key": key, "timestamp": now})
    return True

# ==================== DEFAULT DATA ====================

DEFAULT_TOOLS = [
    {
        "id": "compress-image",
        "name": "Compress Image",
        "slug": "compress-image",
        "category": "image-tools",
        "description": "Reduce image file size to 20KB, 50KB, or 100KB while maintaining quality",
        "seo_title": "Compress Image Online Free - Reduce Image Size to 20KB, 50KB, 100KB",
        "seo_description": "Free online image compressor. Reduce image file size to exactly 20KB, 50KB, or 100KB. Fast, secure, browser-based compression.",
        "related_tools": ["resize-image", "jpg-to-png", "crop-image"],
        "enabled": True
    },
    {
        "id": "resize-image",
        "name": "Resize Image",
        "slug": "resize-image",
        "category": "image-tools",
        "description": "Resize images to custom dimensions or standard passport photo sizes",
        "seo_title": "Resize Image Online Free - Custom Dimensions & Passport Size",
        "seo_description": "Free online image resizer. Resize photos to any dimension or passport size for India, US, UK. Fast browser-based resizing.",
        "related_tools": ["compress-image", "crop-image", "jpg-to-png"],
        "enabled": True
    },
    {
        "id": "jpg-to-png",
        "name": "JPG to PNG",
        "slug": "jpg-to-png",
        "category": "file-conversion-tools",
        "description": "Convert JPG/JPEG images to PNG format with transparency support",
        "seo_title": "JPG to PNG Converter - Free Online Image Format Converter",
        "seo_description": "Convert JPG to PNG online free. Instant conversion with transparency support. No upload needed, process in browser.",
        "related_tools": ["png-to-jpg", "compress-image", "image-to-pdf"],
        "enabled": True
    },
    {
        "id": "png-to-jpg",
        "name": "PNG to JPG",
        "slug": "png-to-jpg",
        "category": "file-conversion-tools",
        "description": "Convert PNG images to JPG format for smaller file sizes",
        "seo_title": "PNG to JPG Converter - Free Online Image Format Converter",
        "seo_description": "Convert PNG to JPG online free. Reduce file size by converting to JPEG format. Fast, secure, browser-based.",
        "related_tools": ["jpg-to-png", "compress-image", "image-to-pdf"],
        "enabled": True
    },
    {
        "id": "image-to-pdf",
        "name": "Image to PDF",
        "slug": "image-to-pdf",
        "category": "file-conversion-tools",
        "description": "Convert single or multiple images to PDF documents",
        "seo_title": "Image to PDF Converter - Convert JPG, PNG to PDF Online Free",
        "seo_description": "Convert images to PDF online free. Combine multiple JPG, PNG images into one PDF. Fast, secure conversion.",
        "related_tools": ["compress-pdf", "merge-pdf", "jpg-to-png"],
        "enabled": True
    },
    {
        "id": "compress-pdf",
        "name": "Compress PDF",
        "slug": "compress-pdf",
        "category": "pdf-tools",
        "description": "Reduce PDF file size while maintaining document quality",
        "seo_title": "Compress PDF Online Free - Reduce PDF File Size",
        "seo_description": "Compress PDF files online free. Reduce PDF size while keeping quality. Fast, secure, browser-based compression.",
        "related_tools": ["merge-pdf", "image-to-pdf"],
        "enabled": True
    },
    {
        "id": "merge-pdf",
        "name": "Merge PDF",
        "slug": "merge-pdf",
        "category": "pdf-tools",
        "description": "Combine multiple PDF files into a single document",
        "seo_title": "Merge PDF Online Free - Combine PDF Files",
        "seo_description": "Merge PDF files online free. Combine multiple PDFs into one document. Fast, secure, browser-based.",
        "related_tools": ["compress-pdf", "image-to-pdf"],
        "enabled": True
    },
    {
        "id": "crop-image",
        "name": "Crop Image",
        "slug": "crop-image",
        "category": "image-tools",
        "description": "Crop images to custom dimensions or preset aspect ratios",
        "seo_title": "Crop Image Online Free - Cut & Trim Photos Instantly",
        "seo_description": "Crop images online free. Cut and trim photos to any size or aspect ratio. Fast, secure, browser-based cropping.",
        "related_tools": ["resize-image", "compress-image", "passport-photo"],
        "enabled": True
    },
    {
        "id": "passport-photo",
        "name": "Passport Photo Maker",
        "slug": "passport-photo",
        "category": "image-tools",
        "description": "Create passport and visa photos in standard sizes (US 2×2, UK 35×45mm, Schengen)",
        "seo_title": "Passport Photo Maker - Create 2x2, 35x45mm Photos Online Free",
        "seo_description": "Create passport and visa photos online free. US passport 2×2 inch, UK/EU 35×45mm, Schengen visa sizes. Instant processing with white background.",
        "related_tools": ["crop-image", "resize-image", "compress-image"],
        "enabled": True
    }
]

DEFAULT_CATEGORIES = [
    {
        "id": "image-tools",
        "name": "Image Tools",
        "slug": "image-tools",
        "description": "Free online image editing tools - compress, resize, crop, and convert images",
        "seo_title": "Free Online Image Tools - Compress, Resize, Crop & Convert",
        "seo_description": "Free online image tools. Compress images, resize photos, crop pictures, convert formats. All processing in your browser.",
        "seo_content": "Our free online image tools help you edit and optimize images without installing any software. All processing happens in your browser, ensuring your files stay private and secure."
    },
    {
        "id": "pdf-tools",
        "name": "PDF Tools",
        "slug": "pdf-tools",
        "description": "Free online PDF tools - compress, merge, and convert PDF documents",
        "seo_title": "Free Online PDF Tools - Compress, Merge & Convert PDFs",
        "seo_description": "Free online PDF tools. Compress PDF files, merge multiple PDFs, convert images to PDF. Fast, secure, browser-based.",
        "seo_content": "Our free PDF tools help you manage PDF documents without any software. Compress large PDFs, merge multiple files, or convert images to PDF format."
    },
    {
        "id": "file-conversion-tools",
        "name": "File Conversion Tools",
        "slug": "file-conversion-tools",
        "description": "Free online file converters - convert between image and document formats",
        "seo_title": "Free Online File Converters - JPG, PNG, PDF Conversion",
        "seo_description": "Free online file conversion tools. Convert JPG to PNG, PNG to JPG, images to PDF. Fast, secure, browser-based.",
        "seo_content": "Convert files between different formats instantly. Our browser-based converters support all major image and document formats."
    }
]

# ==================== INITIALIZATION ====================

async def init_default_data():
    """Initialize default tools and categories if not exist"""
    # Check if tools exist
    tool_count = await db.tools.count_documents({})
    if tool_count == 0:
        await db.tools.insert_many(DEFAULT_TOOLS)
        logger.info("Initialized default tools")
    
    # Check if categories exist
    cat_count = await db.categories.count_documents({})
    if cat_count == 0:
        await db.categories.insert_many(DEFAULT_CATEGORIES)
        logger.info("Initialized default categories")

# ==================== API ENDPOINTS ====================

@api_router.get("/")
async def root():
    return {"message": "MyGuyAI Tools API", "status": "online"}

@api_router.get("/health")
async def health():
    return {"status": "healthy"}

# ---------- Public Endpoints ----------

@api_router.get("/tools")
async def get_tools():
    """Get all enabled tools grouped by category"""
    tools = await db.tools.find({"enabled": True}, {"_id": 0}).to_list(100)
    categories = await db.categories.find({}, {"_id": 0}).to_list(20)
    
    # Use defaults if empty
    if not tools:
        tools = DEFAULT_TOOLS
    if not categories:
        categories = DEFAULT_CATEGORIES
    
    # Group tools by category
    categorized = {}
    for cat in categories:
        categorized[cat["id"]] = {
            **cat,
            "tools": [t for t in tools if t.get("category") == cat["id"]]
        }
    
    return {
        "tools": tools,
        "categories": list(categorized.values())
    }

@api_router.get("/tool/{slug}")
async def get_tool(slug: str):
    """Get single tool by slug"""
    tool = await db.tools.find_one({"slug": slug, "enabled": True}, {"_id": 0})
    if not tool:
        # Check defaults
        tool = next((t for t in DEFAULT_TOOLS if t["slug"] == slug), None)
    if not tool:
        raise HTTPException(status_code=404, detail="Tool not found")
    return tool

@api_router.get("/category/{slug}")
async def get_category(slug: str):
    """Get category with its tools"""
    category = await db.categories.find_one({"slug": slug}, {"_id": 0})
    if not category:
        category = next((c for c in DEFAULT_CATEGORIES if c["slug"] == slug), None)
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")
    
    tools = await db.tools.find({"category": slug, "enabled": True}, {"_id": 0}).to_list(50)
    if not tools:
        tools = [t for t in DEFAULT_TOOLS if t.get("category") == slug]
    
    return {**category, "tools": tools}

@api_router.get("/settings")
async def get_settings():
    """Get public site settings"""
    settings = await db.settings.find_one({"type": "site"}, {"_id": 0})
    return settings or {
        "flash_message": {"enabled": False},
        "homepage_title": "Free Online Tools – Compress Images, Convert JPG to PNG, Merge PDF & More",
        "homepage_description": "MyGuyAI offers free online tools for image compression, resizing, format conversion, and PDF management. All processing happens in your browser - fast, secure, and private."
    }

@api_router.post("/track-usage")
async def track_usage(request: Request, tool_id: str = Form(...)):
    """Track tool usage for analytics"""
    if not await check_rate_limit(request):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    await db.usage.insert_one({
        "tool_id": tool_id,
        "timestamp": datetime.now(timezone.utc),
        "ip_hash": hashlib.md5((request.client.host or "").encode()).hexdigest()[:8]
    })
    return {"success": True}

# ---------- SEO Endpoints ----------

@api_router.get("/sitemap.xml")
async def sitemap():
    """Generate sitemap.xml"""
    tools = await db.tools.find({"enabled": True}, {"_id": 0, "slug": 1}).to_list(100)
    if not tools:
        tools = [{"slug": t["slug"]} for t in DEFAULT_TOOLS]
    
    categories = await db.categories.find({}, {"_id": 0, "slug": 1}).to_list(20)
    if not categories:
        categories = [{"slug": c["slug"]} for c in DEFAULT_CATEGORIES]
    
    base_url = "https://myguyai.com"
    
    urls = [
        f"<url><loc>{base_url}/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>",
        f"<url><loc>{base_url}/about</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>",
        f"<url><loc>{base_url}/contact</loc><changefreq>monthly</changefreq><priority>0.5</priority></url>",
        f"<url><loc>{base_url}/privacy-policy</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>",
        f"<url><loc>{base_url}/terms</loc><changefreq>monthly</changefreq><priority>0.3</priority></url>",
    ]
    
    for cat in categories:
        urls.append(f"<url><loc>{base_url}/{cat['slug']}</loc><changefreq>weekly</changefreq><priority>0.8</priority></url>")
    
    for tool in tools:
        urls.append(f"<url><loc>{base_url}/{tool['slug']}</loc><changefreq>weekly</changefreq><priority>0.9</priority></url>")
    
    sitemap_xml = f'''<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
{chr(10).join(urls)}
</urlset>'''
    
    return Response(content=sitemap_xml, media_type="application/xml")

@api_router.get("/robots.txt")
async def robots():
    """Generate robots.txt"""
    robots_txt = """User-agent: *
Allow: /

Sitemap: https://myguyai.com/api/sitemap.xml

# Disallow admin
Disallow: /admin
"""
    return Response(content=robots_txt, media_type="text/plain")

@api_router.get("/ads.txt")
async def ads_txt():
    """Serve ads.txt for Google AdSense verification"""
    return Response(content=ADS_TXT_CONTENT, media_type="text/plain")

# ---------- Turnstile Bot Protection ----------

@api_router.post("/turnstile/verify")
async def turnstile_verify(request: Request, body: TurnstileVerifyRequest):
    """Verify Cloudflare Turnstile token"""
    # Get client IP
    client_ip = request.client.host if request.client else None
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # Verify token
    is_valid = await verify_turnstile_token(body.token, client_ip)
    
    if is_valid:
        return TurnstileVerifyResponse(success=True, message="Verification successful")
    else:
        raise HTTPException(status_code=403, detail="Bot verification failed")

@api_router.get("/turnstile/status")
async def turnstile_status():
    """Check if Turnstile is enabled"""
    return {"enabled": TURNSTILE_ENABLED}

# ==================== CMS AUTHENTICATION ====================

@api_router.post("/cms/login")
async def cms_login(request: CMSLoginRequest):
    """Login to CMS and get JWT token"""
    user = await db.cms_users.find_one({"email": request.email}, {"_id": 0})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if user.get('password_hash') != hash_password(request.password):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.get('active', True):
        raise HTTPException(status_code=401, detail="Account is disabled")
    
    token = create_jwt_token(user)
    
    # Return user without password
    user_data = {k: v for k, v in user.items() if k != 'password_hash'}
    
    return {"token": token, "user": user_data}

@api_router.get("/cms/me")
async def cms_get_me(user: dict = Depends(get_current_user)):
    """Get current logged-in user info"""
    return {"user": user, "permissions": ROLES.get(user.get('role'), {}).get('permissions', [])}

@api_router.post("/cms/logout")
async def cms_logout():
    """Logout (client should discard token)"""
    return {"success": True}

# ==================== CMS USER MANAGEMENT (Super Admin Only) ====================

@api_router.get("/cms/users")
async def cms_get_users(user: dict = Depends(get_current_user)):
    """Get all CMS users (Super Admin only)"""
    if user.get('role') != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    
    users = await db.cms_users.find({}, {"_id": 0, "password_hash": 0}).to_list(100)
    return {"users": users}

@api_router.post("/cms/users")
async def cms_create_user(new_user: CMSUserCreate, user: dict = Depends(get_current_user)):
    """Create new CMS user (Super Admin only)"""
    if user.get('role') != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    
    # Check if email already exists
    existing = await db.cms_users.find_one({"email": new_user.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")
    
    # Validate role
    if new_user.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {', '.join(ROLES.keys())}")
    
    user_doc = {
        "email": new_user.email,
        "name": new_user.name,
        "role": new_user.role,
        "password_hash": hash_password(new_user.password),
        "active": True,
        "created_at": datetime.now(timezone.utc),
        "created_by": user.get('email')
    }
    
    await db.cms_users.insert_one(user_doc)
    
    return {"success": True, "user": {k: v for k, v in user_doc.items() if k not in ['_id', 'password_hash']}}

@api_router.put("/cms/users/{email}")
async def cms_update_user(email: str, update: CMSUserUpdate, user: dict = Depends(get_current_user)):
    """Update CMS user (Super Admin only)"""
    if user.get('role') != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    
    # Prevent self-demotion
    if email == user.get('email') and update.role and update.role != 'super_admin':
        raise HTTPException(status_code=400, detail="Cannot change your own role")
    
    update_doc = {}
    if update.name:
        update_doc['name'] = update.name
    if update.role:
        if update.role not in ROLES:
            raise HTTPException(status_code=400, detail=f"Invalid role")
        update_doc['role'] = update.role
    if update.active is not None:
        update_doc['active'] = update.active
    if update.password:
        update_doc['password_hash'] = hash_password(update.password)
    
    if update_doc:
        update_doc['updated_at'] = datetime.now(timezone.utc)
        await db.cms_users.update_one({"email": email}, {"$set": update_doc})
    
    return {"success": True}

@api_router.delete("/cms/users/{email}")
async def cms_delete_user(email: str, user: dict = Depends(get_current_user)):
    """Delete CMS user (Super Admin only)"""
    if user.get('role') != 'super_admin':
        raise HTTPException(status_code=403, detail="Super Admin access required")
    
    if email == user.get('email'):
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    
    await db.cms_users.delete_one({"email": email})
    return {"success": True}

# ==================== CMS CONTENT EDITING ====================

@api_router.put("/cms/content")
async def cms_update_content(update: ContentUpdate, user: dict = Depends(get_current_user)):
    """Update tool content (SEO Manager can edit SEO, Editor can edit content)"""
    field = update.field
    
    # Check permissions based on field
    if field in ['seo_title', 'seo_description']:
        if not check_permission(user, 'edit_seo') and not check_permission(user, 'edit_content'):
            raise HTTPException(status_code=403, detail="Permission denied")
    elif field in ['description', 'content']:
        if not check_permission(user, 'edit_content'):
            raise HTTPException(status_code=403, detail="Permission denied")
    else:
        raise HTTPException(status_code=400, detail="Invalid field")
    
    await db.tools.update_one(
        {"id": update.tool_id},
        {"$set": {field: update.value, "updated_at": datetime.now(timezone.utc), "updated_by": user.get('email')}}
    )
    
    return {"success": True}

@api_router.put("/cms/faqs")
async def cms_update_faqs(update: FAQUpdate, user: dict = Depends(get_current_user)):
    """Update or create FAQs for a tool (Editor permission)"""
    if not check_permission(user, 'edit_faqs') and not check_permission(user, 'create_faqs'):
        raise HTTPException(status_code=403, detail="Permission denied")
    
    faqs = [{"question": f.question, "answer": f.answer} for f in update.faqs]
    
    await db.tools.update_one(
        {"id": update.tool_id},
        {"$set": {"faqs": faqs, "updated_at": datetime.now(timezone.utc), "updated_by": user.get('email')}}
    )
    
    return {"success": True}

@api_router.get("/cms/tools")
async def cms_get_tools_for_editing(user: dict = Depends(get_current_user)):
    """Get all tools for CMS editing"""
    tools = await db.tools.find({}, {"_id": 0}).to_list(100)
    if not tools:
        tools = DEFAULT_TOOLS
    return {"tools": tools}

@api_router.get("/cms/roles")
async def cms_get_roles():
    """Get available roles"""
    return {"roles": ROLES}

# ---------- Admin Endpoints ----------

@api_router.post("/admin/login")
async def admin_login(request: AdminLoginRequest):
    if request.password == ADMIN_PASSWORD:
        token = hashlib.sha256(f"{ADMIN_PASSWORD}{datetime.now().isoformat()}".encode()).hexdigest()
        return {"success": True, "token": token}
    raise HTTPException(status_code=401, detail="Invalid password")

@api_router.get("/admin/tools")
async def admin_get_tools():
    """Get all tools for admin"""
    tools = await db.tools.find({}, {"_id": 0}).to_list(100)
    if not tools:
        tools = DEFAULT_TOOLS
    return {"tools": tools}

@api_router.put("/admin/tool/{tool_id}")
async def admin_update_tool(tool_id: str, tool: ToolConfig):
    """Update a tool"""
    await db.tools.update_one(
        {"id": tool_id},
        {"$set": tool.dict()},
        upsert=True
    )
    return {"success": True}

@api_router.get("/admin/categories")
async def admin_get_categories():
    """Get all categories for admin"""
    categories = await db.categories.find({}, {"_id": 0}).to_list(20)
    if not categories:
        categories = DEFAULT_CATEGORIES
    return {"categories": categories}

@api_router.put("/admin/category/{cat_id}")
async def admin_update_category(cat_id: str, category: CategoryConfig):
    """Update a category"""
    await db.categories.update_one(
        {"id": cat_id},
        {"$set": category.dict()},
        upsert=True
    )
    return {"success": True}

@api_router.put("/admin/settings")
async def admin_update_settings(
    flash_enabled: bool = Form(None),
    flash_message: str = Form(None),
    flash_link: str = Form(None),
    flash_link_text: str = Form(None),
    homepage_title: str = Form(None),
    homepage_description: str = Form(None)
):
    """Update site settings"""
    update_data = {"type": "site"}
    
    if flash_enabled is not None or flash_message:
        update_data["flash_message"] = {
            "enabled": flash_enabled or False,
            "message": flash_message or "",
            "link": flash_link,
            "link_text": flash_link_text
        }
    
    if homepage_title:
        update_data["homepage_title"] = homepage_title
    if homepage_description:
        update_data["homepage_description"] = homepage_description
    
    await db.settings.update_one(
        {"type": "site"},
        {"$set": update_data},
        upsert=True
    )
    return {"success": True}

@api_router.get("/admin/stats")
async def admin_get_stats():
    """Get usage statistics"""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(days=1)
    week_ago = now - timedelta(days=7)
    
    today_usage = await db.usage.count_documents({"timestamp": {"$gte": day_ago}})
    week_usage = await db.usage.count_documents({"timestamp": {"$gte": week_ago}})
    total_usage = await db.usage.count_documents({})
    
    # Top tools
    pipeline = [
        {"$group": {"_id": "$tool_id", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5}
    ]
    top_tools = await db.usage.aggregate(pipeline).to_list(5)
    
    return {
        "today": today_usage,
        "week": week_usage,
        "total": total_usage,
        "top_tools": top_tools
    }

# Include router
app.include_router(api_router)

# ===========================================
# PHASE 6: STATIC SEO PAGE ROUTING
# ===========================================

# List of SSG compression page slugs (clean URLs)
SSG_COMPRESSION_PATTERN = re.compile(r'^/compress-image-to-\d+(kb|mb)$')

# Trust pages that have .html files
TRUST_PAGES = ['about', 'contact', 'privacy-policy', 'terms']

# Google Search Console HTML File Verification (MUST NOT REDIRECT)
@app.get("/google377e4bb03cdfe326.html")
async def serve_gsc_verification():
    """Serve GSC HTML verification file - MUST return 200, NO redirect"""
    html_file = FRONTEND_PUBLIC_DIR / "google377e4bb03cdfe326.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html", status_code=200)
    raise HTTPException(status_code=404, detail="Verification file not found")

@app.get("/compress-image-to-{size}")
async def serve_compression_page(size: str):
    """Serve static SSG compression pages at clean URLs"""
    slug = f"compress-image-to-{size}"
    html_file = FRONTEND_PUBLIC_DIR / f"{slug}.html"
    
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    
    # Return 404 page
    error_page = FRONTEND_PUBLIC_DIR / "404.html"
    if error_page.exists():
        return FileResponse(error_page, media_type="text/html", status_code=404)
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/about")
async def serve_about():
    """Serve about page at clean URL"""
    html_file = FRONTEND_PUBLIC_DIR / "about.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/contact")
async def serve_contact():
    """Serve contact page at clean URL"""
    html_file = FRONTEND_PUBLIC_DIR / "contact.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/privacy-policy")
async def serve_privacy():
    """Serve privacy policy at clean URL"""
    html_file = FRONTEND_PUBLIC_DIR / "privacy-policy.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/terms")
async def serve_terms():
    """Serve terms page at clean URL"""
    html_file = FRONTEND_PUBLIC_DIR / "terms.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

# Trailing slash redirects (301)
@app.get("/compress-image-to-{size}/")
async def redirect_compression_trailing(size: str):
    """301 redirect trailing slash to clean URL"""
    return RedirectResponse(url=f"/compress-image-to-{size}", status_code=301)

@app.get("/about/")
async def redirect_about_trailing():
    return RedirectResponse(url="/about", status_code=301)

@app.get("/contact/")
async def redirect_contact_trailing():
    return RedirectResponse(url="/contact", status_code=301)

@app.get("/privacy-policy/")
async def redirect_privacy_trailing():
    return RedirectResponse(url="/privacy-policy", status_code=301)

@app.get("/terms/")
async def redirect_terms_trailing():
    return RedirectResponse(url="/terms", status_code=301)

# Blog and Guides directories
@app.get("/blog")
async def serve_blog():
    """Serve blog index page"""
    html_file = FRONTEND_PUBLIC_DIR / "blog" / "index.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/blog/{slug}")
async def serve_blog_post(slug: str):
    """Serve individual blog posts at clean URLs"""
    html_file = FRONTEND_PUBLIC_DIR / "blog" / f"{slug}.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    # Return 404 page
    error_page = FRONTEND_PUBLIC_DIR / "404.html"
    if error_page.exists():
        return FileResponse(error_page, media_type="text/html", status_code=404)
    raise HTTPException(status_code=404, detail="Blog post not found")

@app.get("/guides")
async def serve_guides():
    """Serve guides index page"""
    html_file = FRONTEND_PUBLIC_DIR / "guides" / "index.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

# Phase 7: New Programmatic Pages
PROGRAMMATIC_SLUGS = [
    'resize-image-for-passport',
    'compress-image-for-ssc-form', 
    'compress-image-for-upsc',
    'best-image-size-for-instagram'
]

@app.get("/resize-image-for-passport")
async def serve_resize_passport():
    """Serve resize image for passport page"""
    html_file = FRONTEND_PUBLIC_DIR / "resize-image-for-passport.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/compress-image-for-ssc-form")
async def serve_ssc_compressor():
    """Serve SSC form image compressor page"""
    html_file = FRONTEND_PUBLIC_DIR / "compress-image-for-ssc-form.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/compress-image-for-upsc")
async def serve_upsc_compressor():
    """Serve UPSC form image compressor page"""
    html_file = FRONTEND_PUBLIC_DIR / "compress-image-for-upsc.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

@app.get("/best-image-size-for-instagram")
async def serve_instagram_guide():
    """Serve Instagram image size guide page"""
    html_file = FRONTEND_PUBLIC_DIR / "best-image-size-for-instagram.html"
    if html_file.exists():
        return FileResponse(html_file, media_type="text/html")
    raise HTTPException(status_code=404, detail="Page not found")

# Serve 404.html for unmatched SSG routes
@app.exception_handler(404)
async def custom_404_handler(request: Request, exc: HTTPException):
    """Custom 404 handler - serve 404.html for SEO routes"""
    path = request.url.path
    
    # Check if this is an SSG route that doesn't exist
    if SSG_COMPRESSION_PATTERN.match(path) or path.lstrip('/') in TRUST_PAGES:
        error_page = FRONTEND_PUBLIC_DIR / "404.html"
        if error_page.exists():
            return FileResponse(error_page, media_type="text/html", status_code=404)
    
    # Default JSON error for API routes
    return Response(content='{"detail": "Not found"}', status_code=404, media_type="application/json")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    await init_default_data()
    await init_super_admin()
    logger.info("MyGuyAI Tools API started")

async def init_super_admin():
    """Initialize Super Admin user if not exists"""
    existing = await db.cms_users.find_one({"email": "admin@myguyai.com"})
    if not existing:
        # Create super admin with password from environment or secure default
        super_admin_password = os.environ.get('SUPER_ADMIN_PASSWORD', 'MyGuyAI@2024!')
        admin_user = {
            "email": "admin@myguyai.com",
            "name": "Super Admin",
            "role": "super_admin",
            "password_hash": hash_password(super_admin_password),
            "active": True,
            "created_at": datetime.now(timezone.utc),
            "created_by": "system"
        }
        await db.cms_users.insert_one(admin_user)
        logger.info("Super Admin user created: admin@myguyai.com")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
