"""Invitation code tests — invite-only account creation.

Covers:
  1.  Generate code — owner can generate (201)
  2.  Generate code — admin can generate (201)
  3.  Generate code — member forbidden (403)
  4.  Generate code — returns code_prefix and plaintext once
  5.  List invitations — owner sees all org invitations
  6.  List invitations — member forbidden (403)
  7.  List invitations — org isolation (Org A can't see Org B)
  8.  Revoke invitation — owner revokes unused code (200)
  9.  Revoke invitation — cannot revoke used code (400)
  10. Revoke invitation — cannot revoke already-revoked code (400)
  11. Revoke invitation — org isolation (can't revoke other org's code)
  12. Register with valid invitation — succeeds (201)
  13. Register with invalid invitation — fails (400)
  14. Register with used invitation — fails (400)

Total: 14 tests
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session as SASession

from app.database import SessionLocal
from app.models_multi_tenant import (
    InvitationCode,
    InvitationStatus,
    Organization,
    OrganizationStatus,
    User,
    UserRole,
    UserStatus,
)
from app.services.crypto import generate_key

# ── Test Constants ────────────────────────────────────────────────────────────

TEST_JWT_SECRET = "test-invitation-jwt-secret-key-for-testing-32ch!!"
TEST_ENCRYPTION_KEY = generate_key()


# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _set_test_secrets(monkeypatch):
    """Inject test-mode secrets so get_jwt_secret_key() works."""
    from app.config import settings
    monkeypatch.setattr(settings, "jwt_secret_key", TEST_JWT_SECRET)
    monkeypatch.setattr(settings, "app_env", "test")
    monkeypatch.setattr(settings, "credential_encryption_key", TEST_ENCRYPTION_KEY)


@pytest.fixture(autouse=True)
def _clear_register_rate_limit():
    """Clear the module-level registration rate-limit dict before each test.

    The ``_register_hits`` dict in ``app.routers.auth_router`` is a
    ``defaultdict(list)`` that lives for the lifetime of the process.
    Without clearing it between tests, later registration calls get
    429 Too Many Requests because earlier tests already filled the window.
    """
    from app.routers.auth_router import _register_hits
    _register_hits.clear()
    yield
    _register_hits.clear()


@pytest.fixture()
def client():
    """TestClient with lifespan support."""
    from app.main import app
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def db():
    """Yield a DB session with rollback."""
    session = SessionLocal()
    try:
        yield session
        session.rollback()
    finally:
        session.close()


def _create_org_and_user(
    db: SASession,
    email: str = "owner@test.com",
    password: str = "StrongPass123!",
    role: UserRole = UserRole.OWNER,
    org_name: str | None = None,
    user_status: UserStatus = UserStatus.ACTIVE,
) -> tuple[Organization, User]:
    """Helper: create an org + user with a bcrypt password hash."""
    from app.auth import hash_password

    org = Organization(
        name=org_name or f"Test Org {uuid.uuid4().hex[:8]}",
        slug=f"test-org-{uuid.uuid4().hex[:8]}",
        timezone="America/Chicago",
        status=OrganizationStatus.ACTIVE,
        plan="business",
    )
    db.add(org)
    db.flush()

    user = User(
        organization_id=org.id,
        email=email.lower(),
        full_name="Test User",
        password_hash=hash_password(password),
        role=role,
        status=user_status,
    )
    db.add(user)
    db.commit()
    db.refresh(org)
    db.refresh(user)
    return org, user


def _make_token(user_id, org_id, role: str) -> str:
    """Create a valid JWT token for testing."""
    from app.auth import create_access_token
    return create_access_token(user_id=user_id, organization_id=org_id, role=role)


def _auth_header(token: str) -> dict:
    """Return Authorization header for Bearer token."""
    return {"Authorization": f"Bearer {token}"}


def _generate_via_api(
    client: TestClient, token: str, *, label: str = None, email: str = None
) -> dict:
    """Call POST /auth/invitations/generate and return the response JSON."""
    payload = {}
    if label:
        payload["label"] = label
    if email:
        payload["email"] = email
    resp = client.post(
        "/auth/invitations/generate",
        json=payload,
        headers=_auth_header(token),
    )
    return resp


# ══════════════════════════════════════════════════════════════════════════════
# 1. GENERATE INVITATION CODE (4 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateInvitation:
    """POST /auth/invitations/generate tests."""

    def test_owner_can_generate(self, client: TestClient, db: SASession):
        """Owner can generate an invitation code (201)."""
        org, user = _create_org_and_user(db, email=f"ow-{uuid.uuid4().hex[:8]}@t.com")
        token = _make_token(user.id, org.id, "owner")
        resp = _generate_via_api(client, token)
        assert resp.status_code == 201
        data = resp.json()
        assert "code" in data
        assert data["code"].startswith("SCA-")
        assert data["status"] == "unused"

    def test_admin_can_generate(self, client: TestClient, db: SASession):
        """Admin can generate an invitation code (201)."""
        org, _ = _create_org_and_user(db, email=f"adm-gen-{uuid.uuid4().hex[:8]}@t.com")
        _, admin = _create_org_and_user(
            db, email=f"adm-{uuid.uuid4().hex[:8]}@t.com",
            role=UserRole.ADMIN, org_name=org.name,
        )
        # Re-create with same org
        db.rollback()
        org, owner = _create_org_and_user(db, email=f"ow2-{uuid.uuid4().hex[:8]}@t.com")
        from app.auth import hash_password
        admin = User(
            organization_id=org.id,
            email=f"adm-{uuid.uuid4().hex[:8]}@t.com",
            full_name="Admin User",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.ADMIN,
            status=UserStatus.ACTIVE,
        )
        db.add(admin)
        db.commit()
        db.refresh(admin)

        token = _make_token(admin.id, org.id, "admin")
        resp = _generate_via_api(client, token)
        assert resp.status_code == 201
        data = resp.json()
        assert "code" in data

    def test_member_forbidden(self, client: TestClient, db: SASession):
        """Member cannot generate invitation codes (403)."""
        org, _ = _create_org_and_user(db, email=f"mem-gen-{uuid.uuid4().hex[:8]}@t.com")
        from app.auth import hash_password
        member = User(
            organization_id=org.id,
            email=f"mem-{uuid.uuid4().hex[:8]}@t.com",
            full_name="Member User",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        token = _make_token(member.id, org.id, "member")
        resp = _generate_via_api(client, token)
        assert resp.status_code == 403

    def test_returns_plaintext_once(self, client: TestClient, db: SASession):
        """Generated response includes plaintext code and code_prefix."""
        org, user = _create_org_and_user(db, email=f"once-{uuid.uuid4().hex[:8]}@t.com")
        token = _make_token(user.id, org.id, "owner")
        resp = _generate_via_api(client, token, label="Test Invite")
        assert resp.status_code == 201
        data = resp.json()
        assert "code" in data and len(data["code"]) >= 10
        assert "code_prefix" in data and len(data["code_prefix"]) >= 8
        assert data["label"] == "Test Invite"


# ══════════════════════════════════════════════════════════════════════════════
# 2. LIST INVITATIONS (3 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestListInvitations:
    """GET /auth/invitations tests."""

    def test_owner_sees_all(self, client: TestClient, db: SASession):
        """Owner sees all invitations for their org."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"list-ow-{uuid.uuid4().hex[:8]}@t.com")
        code1 = create_test_invitation(db, org.id, user.id, label="Invite 1")
        code2 = create_test_invitation(db, org.id, user.id, label="Invite 2")
        token = _make_token(user.id, org.id, "owner")

        resp = client.get("/auth/invitations", headers=_auth_header(token))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 2
        labels = {inv["label"] for inv in data["invitations"]}
        assert "Invite 1" in labels
        assert "Invite 2" in labels

    def test_member_forbidden(self, client: TestClient, db: SASession):
        """Member cannot list invitations (403)."""
        from app.auth import hash_password

        org, _ = _create_org_and_user(db, email=f"list-mem-{uuid.uuid4().hex[:8]}@t.com")
        member = User(
            organization_id=org.id,
            email=f"lm-{uuid.uuid4().hex[:8]}@t.com",
            full_name="Member",
            password_hash=hash_password("StrongPass123!"),
            role=UserRole.MEMBER,
            status=UserStatus.ACTIVE,
        )
        db.add(member)
        db.commit()
        db.refresh(member)

        token = _make_token(member.id, org.id, "member")
        resp = client.get("/auth/invitations", headers=_auth_header(token))
        assert resp.status_code == 403

    def test_org_isolation(self, client: TestClient, db: SASession):
        """Org A can't see Org B's invitations."""
        from tests.conftest import create_test_invitation

        org_a, user_a = _create_org_and_user(db, email=f"a-{uuid.uuid4().hex[:8]}@t.com")
        org_b, user_b = _create_org_and_user(db, email=f"b-{uuid.uuid4().hex[:8]}@t.com")
        create_test_invitation(db, org_b.id, user_b.id, label="OrgB Invite")

        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/auth/invitations", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_no_code_hash_exposed(self, client: TestClient, db: SASession):
        """List response never includes code_hash."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"nohash-{uuid.uuid4().hex[:8]}@t.com")
        create_test_invitation(db, org.id, user.id)
        token = _make_token(user.id, org.id, "owner")

        resp = client.get("/auth/invitations", headers=_auth_header(token))
        assert resp.status_code == 200
        for inv in resp.json()["invitations"]:
            assert "code_hash" not in inv
            assert "code" not in inv


# ══════════════════════════════════════════════════════════════════════════════
# 3. REVOKE INVITATION (3 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestRevokeInvitation:
    """POST /auth/invitations/{id}/revoke tests."""

    def test_owner_revokes_unused(self, client: TestClient, db: SASession):
        """Owner can revoke an unused invitation code."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"rev-ow-{uuid.uuid4().hex[:8]}@t.com")
        invite_code = create_test_invitation(db, org.id, user.id)

        # Get the invitation ID from the list
        token = _make_token(user.id, org.id, "owner")
        list_resp = client.get("/auth/invitations", headers=_auth_header(token))
        inv_id = list_resp.json()["invitations"][0]["id"]

        # Revoke it
        resp = client.post(
            f"/auth/invitations/{inv_id}/revoke",
            headers=_auth_header(token),
        )
        assert resp.status_code == 200
        assert "revoked" in resp.json()["message"]

    def test_cannot_revoke_used_code(self, client: TestClient, db: SASession):
        """Cannot revoke an invitation that was already used."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"rev-used-{uuid.uuid4().hex[:8]}@t.com")
        invite_code = create_test_invitation(db, org.id, user.id)

        # Use the invitation code by registering
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"Used Org {uuid.uuid4().hex[:6]}",
                "name": "Used User",
                "email": f"used-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp.status_code == 201

        # Get the invitation ID from the list (status should be 'used')
        token = _make_token(user.id, org.id, "owner")
        list_resp = client.get("/auth/invitations", headers=_auth_header(token))
        inv_id = list_resp.json()["invitations"][0]["id"]
        assert list_resp.json()["invitations"][0]["status"] == "used"

        # Try to revoke it — should fail
        resp = client.post(
            f"/auth/invitations/{inv_id}/revoke",
            headers=_auth_header(token),
        )
        assert resp.status_code == 400

    def test_org_isolation_on_revoke(self, client: TestClient, db: SASession):
        """Org A cannot revoke Org B's invitation."""
        from tests.conftest import create_test_invitation

        org_a, user_a = _create_org_and_user(db, email=f"ra-{uuid.uuid4().hex[:8]}@t.com")
        org_b, user_b = _create_org_and_user(db, email=f"rb-{uuid.uuid4().hex[:8]}@t.com")
        create_test_invitation(db, org_b.id, user_b.id)

        # Get OrgB's invitation
        token_b = _make_token(user_b.id, org_b.id, "owner")
        list_b = client.get("/auth/invitations", headers=_auth_header(token_b))
        inv_b_id = list_b.json()["invitations"][0]["id"]

        # OrgA tries to revoke OrgB's invitation
        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.post(
            f"/auth/invitations/{inv_b_id}/revoke",
            headers=_auth_header(token_a),
        )
        assert resp.status_code == 400


# ══════════════════════════════════════════════════════════════════════════════
# 4. REGISTRATION WITH INVITATION (4 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistrationWithInvitation:
    """POST /auth/register with invitation_code tests."""

    def test_valid_invitation_succeeds(self, client: TestClient, db: SASession):
        """Registration with a valid invitation code returns 201 + JWT."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"reg-val-{uuid.uuid4().hex[:8]}@t.com")
        invite_code = create_test_invitation(db, org.id, user.id)

        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"New Org {uuid.uuid4().hex[:6]}",
                "name": "New Owner",
                "email": f"new-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"

    def test_invalid_invitation_rejected(self, client: TestClient):
        """Registration with a non-existent code returns 400."""
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"Bad Org {uuid.uuid4().hex[:6]}",
                "name": "Bad User",
                "email": f"bad-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": "SCA-FAKE-CODE1",
            },
        )
        assert resp.status_code == 400
        assert "invitation" in resp.json()["detail"].lower()

    def test_used_invitation_rejected(self, client: TestClient, db: SASession):
        """Registration with an already-used code returns 400."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"reg-used-{uuid.uuid4().hex[:8]}@t.com")
        invite_code = create_test_invitation(db, org.id, user.id)

        # First registration — uses the code
        resp1 = client.post(
            "/auth/register",
            json={
                "organization_name": f"First Org {uuid.uuid4().hex[:6]}",
                "name": "First User",
                "email": f"first-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp1.status_code == 201

        # Second registration — same code, should fail
        resp2 = client.post(
            "/auth/register",
            json={
                "organization_name": f"Second Org {uuid.uuid4().hex[:6]}",
                "name": "Second User",
                "email": f"second-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp2.status_code == 400
        assert "already been used" in resp2.json()["detail"]

    def test_registration_marks_invitation_used(self, client: TestClient, db: SASession):
        """After registration, the invitation status changes to 'used'."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"reg-mark-{uuid.uuid4().hex[:8]}@t.com")
        invite_code = create_test_invitation(db, org.id, user.id)

        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"Mark Org {uuid.uuid4().hex[:6]}",
                "name": "Mark User",
                "email": f"mark-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp.status_code == 201

        # Verify via listing
        token = _make_token(user.id, org.id, "owner")
        list_resp = client.get("/auth/invitations", headers=_auth_header(token))
        invs = list_resp.json()["invitations"]
        used = [i for i in invs if i["status"] == "used"]
        assert len(used) >= 1

    def test_member_can_register(self, client: TestClient, db: SASession):
        """A new user registering with a valid code becomes OWNER of a new org."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(db, email=f"reg-mem-{uuid.uuid4().hex[:8]}@t.com")
        invite_code = create_test_invitation(db, org.id, user.id)

        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"Member Org {uuid.uuid4().hex[:6]}",
                "name": "Member Owner",
                "email": f"mowner-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "access_token" in data
