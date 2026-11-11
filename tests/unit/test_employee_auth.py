from datetime import datetime, timedelta, timezone
import hashlib
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool
from redis import RedisError

from firmwarex import auth
from firmwarex.api import api
from firmwarex.config import settings
from firmwarex.database import session
from firmwarex.models import Base, Employee, EmployeeSession

CODE = 'test-only-company-code-not-a-real-secret-1234'
PASSWORD = 'test-only-password-12345'
HEADERS = {'Origin': 'http://testserver'}

@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv('FWX_DATABASE_URL', 'sqlite://')
    monkeypatch.setenv('FWX_API_TOKEN', 'test-only-automation-token')
    monkeypatch.setenv('FWX_COMPANY_REGISTRATION_CODE', CODE)
    settings.cache_clear()
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    def db():
        with Session(engine) as value:
            yield value
    api.dependency_overrides[session] = db
    class Store:
        def __init__(self): self.counts = {}
        def eval(self, script, count, key):
            self.counts[key] = self.counts.get(key, 0) + 1
            return self.counts[key]
    store = Store()
    monkeypatch.setattr(auth, 'rate_store', lambda: store)
    with TestClient(api) as value:
        value.engine = engine
        yield value
    api.dependency_overrides.clear()
    engine.dispose()
    settings.cache_clear()

def register(client, **overrides):
    return client.post('/api/v1/auth/register', headers=HEADERS, json={'employee_id': 'emp-001', 'password': PASSWORD, 'company_code': CODE, **overrides})

def login(client, **overrides):
    return client.post('/api/v1/auth/login', headers=HEADERS, json={'employee_id': 'emp-001', 'password': PASSWORD, **overrides})

def test_registration_login_logout_and_password_storage(client):
    assert client.get('/api/v1/firmware').status_code == 401
    assert register(client).status_code == 201
    assert client.get('/api/v1/auth/me').status_code == 401
    with Session(client.engine) as db:
        stored = db.get(Employee, 'EMP-001').password_hash
        assert PASSWORD not in stored and auth.verify_password(PASSWORD, stored)
    response = login(client)
    assert response.status_code == 200
    cookie = response.headers['set-cookie']
    assert 'HttpOnly' in cookie and 'SameSite=strict' in cookie and 'Max-Age=28800' in cookie
    raw = client.cookies.get(auth.COOKIE)
    with Session(client.engine) as db:
        record = db.scalar(select(EmployeeSession))
        assert record.token_hash == hashlib.sha256(raw.encode()).hexdigest()
        assert record.token_hash != raw
    assert client.get('/api/v1/auth/me').json() == {'employee_id': 'EMP-001'}
    assert client.get('/api/v1/firmware').status_code == 200
    assert client.post('/api/v1/auth/logout', headers=HEADERS).status_code == 204
    client.cookies.set(auth.COOKIE, raw)
    assert client.get('/api/v1/auth/me').status_code == 401

def test_wrong_company_code_creates_no_employee(client):
    assert register(client, company_code='wrong-code').status_code == 403
    with Session(client.engine) as db:
        assert db.scalar(select(Employee)) is None

def test_duplicate_case_insensitive_id_preserves_password(client):
    assert register(client).status_code == 201
    assert register(client, employee_id='EMP-001', password='different-test-password').status_code == 409
    assert login(client).status_code == 200

def test_invalid_credentials_generic_and_no_secret_echo(client):
    register(client)
    wrong = login(client, password='wrong-password-1234')
    missing = login(client, employee_id='EMP-UNKNOWN')
    assert wrong.status_code == missing.status_code == 401
    assert wrong.json() == missing.json()
    bad = register(client, password='tiny', company_code='sensitive-code')
    assert bad.status_code == 422
    assert 'tiny' not in bad.text and 'sensitive-code' not in bad.text

def test_csrf_rejected_for_login_and_authenticated_mutation(client):
    body = {'employee_id':'emp-001', 'password':PASSWORD}
    assert client.post('/api/v1/auth/login', json=body).status_code == 403
    assert client.post('/api/v1/auth/login', headers={'Origin':'https://evil.example'}, json=body).status_code == 403
    register(client); login(client)
    assert client.post('/api/v1/firmware/00000000-0000-0000-0000-000000000000/name', data={'display_name':'changed'}, headers={'Origin':'http://evil.example'}).status_code == 403
    assert client.post('/api/v1/auth/logout', headers={'Origin':'null'}).status_code == 403

def test_expired_session_rejected(client):
    register(client); login(client)
    with Session(client.engine) as db:
        record = db.scalar(select(EmployeeSession))
        record.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    assert client.get('/api/v1/firmware').status_code == 401

def test_registration_disabled_without_valid_company_configuration(client, monkeypatch):
    monkeypatch.setenv('FWX_COMPANY_REGISTRATION_CODE', '')
    settings.cache_clear()
    assert register(client).status_code == 503

def test_login_attempts_rate_limited(client):
    for _ in range(10): assert login(client).status_code == 401
    assert login(client).status_code == 429

def test_rate_store_failure_denies_login(client, monkeypatch):
    class Broken:
        def eval(self, *args): raise RedisError('offline')
    monkeypatch.setattr(auth, 'rate_store', lambda: Broken())
    assert login(client).status_code == 503

def test_existing_bearer_api_access_preserved(client):
    assert client.get('/api/v1/firmware', headers={'Authorization':'Bearer test-only-automation-token'}).status_code == 200
    assert client.get('/api/v1/firmware', headers={'Authorization':'Bearer invalid'}).status_code == 401

def test_new_login_replaces_current_session_and_secure_cookie_option(client, monkeypatch):
    register(client); login(client)
    old = client.cookies.get(auth.COOKIE)
    monkeypatch.setenv('FWX_SESSION_COOKIE_SECURE', 'true'); settings.cache_clear()
    response = login(client)
    assert 'Secure' in response.headers['set-cookie']
    with Session(client.engine) as db:
        assert db.get(EmployeeSession, hashlib.sha256(old.encode()).hexdigest()) is None
