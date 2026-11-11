"""Employee onboarding and shared-workspace authentication."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, Response, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field, field_validator
from redis import Redis, RedisError
from sqlalchemy import delete
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from firmwarex.config import settings
from firmwarex.database import session
from firmwarex.models import Employee, EmployeeSession

router = APIRouter(prefix='/api/v1/auth', tags=['Employee access'])
bearer = HTTPBearer(auto_error=False)
COOKIE = 'fwx_session'
SESSION_SECONDS = 8 * 60 * 60
ITERATIONS = 600_000

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), ITERATIONS).hex()
    return f'pbkdf2_sha256${ITERATIONS}${salt}${digest}'

def verify_password(password, encoded):
    try:
        algorithm, rounds, salt, expected = encoded.split('$')
        if algorithm != 'pbkdf2_sha256' or int(rounds) != ITERATIONS:
            return False
        actual = hash_password(password, salt).rsplit('$', 1)[1]
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

# Unknown IDs still perform the same password KDF as known employees.
DUMMY_HASH = hash_password(secrets.token_urlsafe(32))

class Credentials(BaseModel):
    employee_id: str = Field(min_length=1, max_length=64, pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]*$')
    password: str = Field(min_length=12, max_length=128)

    @field_validator('employee_id')
    @classmethod
    def normalize_id(cls, value):
        return value.upper()

class Registration(Credentials):
    company_code: str = Field(min_length=1, max_length=256)

def same_origin(request):
    origin = request.headers.get('origin')
    if not origin or urlsplit(origin).netloc != request.url.netloc or urlsplit(origin).scheme != request.url.scheme:
        raise HTTPException(403, 'Open this form from the FirmwareX website.')
    if request.headers.get('sec-fetch-site') not in (None, 'same-origin', 'none'):
        raise HTTPException(403, 'Cross-site request rejected.')

@lru_cache
def rate_store():
    return Redis.from_url(settings().redis_url, socket_connect_timeout=2, socket_timeout=2)

def throttle(request, employee_id):
    # Atomic counters shared by API workers; never store raw IDs or addresses.
    script = "local n=redis.call('INCR',KEYS[1]); if n==1 then redis.call('EXPIRE',KEYS[1],300) end; return n"
    address = request.client.host if request.client else 'unknown'
    for scope, value, limit in [('ip', address, 30), ('employee', employee_id, 10)]:
        digest = hmac.digest(settings().api_token.encode(), value.encode(), 'sha256').hex()
        try:
            count = rate_store().eval(script, 1, 'fwx:auth:' + scope + ':' + digest)
        except RedisError:
            raise HTTPException(503, 'Sign-in is temporarily unavailable. Try again shortly.') from None
        if count > limit:
            raise HTTPException(429, 'Too many attempts. Try again in five minutes.', headers={'Retry-After': '300'})

def current_employee(request, db):
    token = request.cookies.get(COOKIE, '')
    if not token or len(token) > 128:
        raise HTTPException(401, 'Please log in.')
    record = db.get(EmployeeSession, hashlib.sha256(token.encode()).hexdigest())
    if not record:
        raise HTTPException(401, 'Please log in.')
    expiry = record.expires_at
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    if expiry <= datetime.now(timezone.utc):
        raise HTTPException(401, 'Session expired. Please log in again.')
    employee = db.get(Employee, record.employee_id)
    if not employee:
        raise HTTPException(401, 'Please log in.')
    return employee

def authorize(request: Request, credentials: HTTPAuthorizationCredentials | None = Security(bearer), db: Session = Depends(session)):
    # Existing automation keeps its private Bearer token; browsers use cookies.
    if credentials:
        if not hmac.compare_digest(credentials.credentials.encode(), settings().api_token.encode()):
            raise HTTPException(401, 'Invalid API token')
        return
    employee = current_employee(request, db)
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        same_origin(request)
    return employee.employee_id

@router.post('/register', status_code=201)
def register(body: Registration, request: Request, response: Response, db: Session = Depends(session)):
    same_origin(request)
    throttle(request, body.employee_id)
    code = settings().company_registration_code
    if len(code) < 32:
        raise HTTPException(503, 'Employee registration has not been configured.')
    if not hmac.compare_digest(body.company_code.encode(), code.encode()):
        raise HTTPException(403, 'The company registration code is invalid.')
    db.add(Employee(employee_id=body.employee_id, password_hash=hash_password(body.password)))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, 'This employee ID is already registered. Please log in.') from None
    response.headers['Cache-Control'] = 'no-store'
    return {'employee_id': body.employee_id, 'message': 'Account created. You can now log in.'}

@router.post('/login')
def login(body: Credentials, request: Request, response: Response, db: Session = Depends(session)):
    same_origin(request)
    throttle(request, body.employee_id)
    employee = db.get(Employee, body.employee_id)
    valid = verify_password(body.password, employee.password_hash if employee else DUMMY_HASH)
    if not employee or not valid:
        raise HTTPException(401, 'Employee ID or password is incorrect.')
    now = datetime.now(timezone.utc)
    db.execute(delete(EmployeeSession).where(EmployeeSession.expires_at <= now))
    old = request.cookies.get(COOKIE)
    if old:
        db.execute(delete(EmployeeSession).where(EmployeeSession.token_hash == hashlib.sha256(old.encode()).hexdigest()))
    token = secrets.token_urlsafe(32)
    db.add(EmployeeSession(token_hash=hashlib.sha256(token.encode()).hexdigest(), employee_id=employee.employee_id, expires_at=now + timedelta(seconds=SESSION_SECONDS)))
    db.commit()
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, httponly=True, secure=settings().session_cookie_secure, samesite='strict', path='/')
    response.headers['Cache-Control'] = 'no-store'
    return {'employee_id': employee.employee_id}

@router.get('/me')
def me(response: Response, employee_id: str | None = Depends(authorize)):
    response.headers['Cache-Control'] = 'no-store'
    return {'employee_id': employee_id or 'Automation'}

@router.post('/logout', status_code=204)
def logout(request: Request, db: Session = Depends(session)):
    same_origin(request)
    token = request.cookies.get(COOKIE, '')
    db.execute(delete(EmployeeSession).where(EmployeeSession.token_hash == hashlib.sha256(token.encode()).hexdigest()))
    db.commit()
    response = Response(status_code=204, headers={'Cache-Control': 'no-store'})
    response.delete_cookie(COOKIE, path='/', secure=settings().session_cookie_secure, httponly=True, samesite='strict')
    return response
