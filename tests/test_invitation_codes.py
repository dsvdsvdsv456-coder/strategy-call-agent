"""Invitation code tests — invite-only account creation.

Covers:
  1.  Platform-owner (4rats.com@gmail.com) can generate (201)
  2.  Another OWNER cannot generate (403)
  3.  ADMIN cannot generate (403)
  4.  MEMBER cannot generate (403)
  5.  Client/customer account cannot generate (403)
  6.  Platform-owner can list invitations
  7.  Another OWNER cannot list invitations (403)
  8.  Platform-owner can revoke unused invitation
  9.  Another OWNER cannot revoke invitation (403)
  10. Cannot revoke a used invitation (400) — lifecycle test
  11. Org isolation — can't see other org's invitations
  12. No code_hash exposed in list response
  13. Register with valid invitation — succeeds (201)
  14. Register with invalid invitation — fails (400)
  15. Register with used invitation — fails (400)
  16. require_owner_or_admin unit tests (platform-owner email)

Total: 17 tests
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
from app.services.invitation_service import PLATFORM_OWNER_EMAIL

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
    """Clear the module-level registration rate-limit dict before each test."""
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
# 1. PLATFORM-OWNER AUTHORIZATION — GENERATE (7 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestGenerateInvitation:
    """POST /auth/invitations/generate tests."""

    def test_platform_owner_can_generate(self, client: TestClient, db: SASession):
        """Platform-owner (4rats.com@gmail.com) can generate (201)."""
        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
        token = _make_token(user.id, org.id, "owner")
        resp = _generate_via_api(client, token)
        assert resp.status_code == 201
        data = resp.json()
        assert "code" in data
        assert data["code"].startswith("SCA-")
        assert data["status"] == "unused"

    def test_another_owner_cannot_generate(self, client: TestClient, db: SASession):
        """Another OWNER (not platform-owner) cannot generate (403)."""
        org, user = _create_org_and_user(
            db, email=f"ow-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
        token = _make_token(user.id, org.id, "owner")
        resp = _generate_via_api(client, token)
        assert resp.status_code == 403
        assert "platform owner" in resp.json()["detail"].lower()

    def test_admin_cannot_generate(self, client: TestClient, db: SASession):
        """ADMIN cannot generate invitation codes (403)."""
        org, user = _create_org_and_user(
            db, email=f"adm-gen-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
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
        assert resp.status_code == 403
        assert "platform owner" in resp.json()["detail"].lower()

    def test_member_cannot_generate(self, client: TestClient, db: SASession):
        """MEMBER cannot generate invitation codes (403)."""
        org, user = _create_org_and_user(
            db, email=f"mem-gen-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
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
        assert "platform owner" in resp.json()["detail"].lower()

    def test_client_cannot_generate(self, client: TestClient, db: SASession):
        """Client/customer account (via register) cannot generate (403)."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=f"owner-for-client-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
        invite_code = create_test_invitation(db, org.id, user.id)

        # Register a new client via invitation
        resp = client.post(
            "/auth/register",
            json={
                "organization_name": f"Client Org {uuid.uuid4().hex[:6]}",
                "name": "Client User",
                "email": f"client-{uuid.uuid4().hex[:8]}@t.com",
                "password": "StrongPass123!",
                "invitation_code": invite_code,
            },
        )
        assert resp.status_code == 201
        client_token = resp.json()["access_token"]

        # Client tries to generate — should fail
        gen_resp = _generate_via_api(client, client_token)
        assert gen_resp.status_code == 403
        assert "platform owner" in gen_resp.json()["detail"].lower()

    def test_returns_plaintext_once(self, client: TestClient, db: SASession):
        """Generated response includes plaintext code and code_prefix."""
        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
        token = _make_token(user.id, org.id, "owner")
        resp = _generate_via_api(client, token, label="Test Invite")
        assert resp.status_code == 201
        data = resp.json()
        assert "code" in data and len(data["code"]) >= 10
        assert "code_prefix" in data and len(data["code_prefix"]) >= 8
        assert data["label"] == "Test Invite"

    def test_case_insensitive_email(self, client: TestClient, db: SASession):
        """Case-insensitive email comparison: 4RATS.COM@GMAIL.COM also works."""
        org, user = _create_org_and_user(
            db, email="4RATS.COM@GMAIL.COM", role=UserRole.OWNER,
        )
        token = _make_token(user.id, org.id, "owner")
        resp = _generate_via_api(client, token)
        assert resp.status_code == 201
        assert "code" in resp.json()


# ══════════════════════════════════════════════════════════════════════════════
# 2. PLATFORM-OWNER AUTHORIZATION — LIST (4 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestListInvitations:
    """GET /auth/invitations tests."""

    def test_platform_owner_sees_all(self, client: TestClient, db: SASession):
        """Platform-owner sees all invitations for their org."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
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

    def test_another_owner_cannot_list(self, client: TestClient, db: SASession):
        """Another OWNER cannot list invitations (403)."""
        org, user = _create_org_and_user(
            db, email=f"list-ow-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
        token = _make_token(user.id, org.id, "owner")
        resp = client.get("/auth/invitations", headers=_auth_header(token))
        assert resp.status_code == 403
        assert "platform owner" in resp.json()["detail"].lower()

    def test_member_cannot_list(self, client: TestClient, db: SASession):
        """Member cannot list invitations (403)."""
        from app.auth import hash_password

        org, _ = _create_org_and_user(
            db, email=f"list-mem-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
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

    def test_no_code_hash_exposed(self, client: TestClient, db: SASession):
        """List response never includes code_hash."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
        create_test_invitation(db, org.id, user.id)
        token = _make_token(user.id, org.id, "owner")

        resp = client.get("/auth/invitations", headers=_auth_header(token))
        assert resp.status_code == 200
        for inv in resp.json()["invitations"]:
            assert "code_hash" not in inv
            assert "code" not in inv


# ══════════════════════════════════════════════════════════════════════════════
# 3. PLATFORM-OWNER AUTHORIZATION — REVOKE (4 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestRevokeInvitation:
    """POST /auth/invitations/{id}/revoke tests."""

    def test_platform_owner_revokes_unused(self, client: TestClient, db: SASession):
        """Platform-owner can revoke an unused invitation code."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
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

    def test_another_owner_cannot_revoke(self, client: TestClient, db: SASession):
        """Another OWNER cannot revoke invitations (403)."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=f"rev-ow-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
        invite_code = create_test_invitation(db, org.id, user.id)

        token = _make_token(user.id, org.id, "owner")
        # Use the service directly to get an ID since list would also fail
        inv = db.query(InvitationCode).filter(InvitationCode.organization_id == org.id).first()
        assert inv is not None

        resp = client.post(
            f"/auth/invitations/{inv.id}/revoke",
            headers=_auth_header(token),
        )
        assert resp.status_code == 403
        assert "platform owner" in resp.json()["detail"].lower()

    def test_cannot_revoke_used_code(self, client: TestClient, db: SASession):
        """Cannot revoke an invitation that was already used."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
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

    def test_org_isolation(self, client: TestClient, db: SASession):
        """Org A can't see or revoke Org B's invitations."""
        from tests.conftest import create_test_invitation

        org_a, user_a = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
        org_b, user_b = _create_org_and_user(
            db, email=f"b-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
        create_test_invitation(db, org_b.id, user_b.id, label="OrgB Invite")

        # OrgA (platform-owner) sees 0 invitations from OrgB
        token_a = _make_token(user_a.id, org_a.id, "owner")
        resp = client.get("/auth/invitations", headers=_auth_header(token_a))
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0


# ══════════════════════════════════════════════════════════════════════════════
# 4. REGISTRATION WITH INVITATION (5 tests — lifecycle unchanged)
# ══════════════════════════════════════════════════════════════════════════════


class TestRegistrationWithInvitation:
    """POST /auth/register with invitation_code tests."""

    def test_valid_invitation_succeeds(self, client: TestClient, db: SASession):
        """Registration with a valid invitation code returns 201 + JWT."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=f"reg-val-{uuid.uuid4().hex[:8]}@t.com",
        )
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

        org, user = _create_org_and_user(
            db, email=f"reg-used-{uuid.uuid4().hex[:8]}@t.com",
        )
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

        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
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

        # Verify via listing (platform-owner can list)
        token = _make_token(user.id, org.id, "owner")
        list_resp = client.get("/auth/invitations", headers=_auth_header(token))
        invs = list_resp.json()["invitations"]
        used = [i for i in invs if i["status"] == "used"]
        assert len(used) >= 1

    def test_new_user_registers_via_invitation(self, client: TestClient, db: SASession):
        """A new user registering with a valid code gets an account."""
        from tests.conftest import create_test_invitation

        org, user = _create_org_and_user(
            db, email=f"reg-mem-{uuid.uuid4().hex[:8]}@t.com",
        )
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


# ══════════════════════════════════════════════════════════════════════════════
# 5. INVITATION SERVICE UNIT TESTS (2 tests)
# ══════════════════════════════════════════════════════════════════════════════


class TestInvitationServiceAuth:
    """Unit tests for require_owner_or_admin (now platform-owner check)."""

    def test_platform_owner_passes(self, db: SASession):
        """require_owner_or_admin passes for platform-owner email."""
        from app.services.invitation_service import require_owner_or_admin

        org, user = _create_org_and_user(
            db, email=PLATFORM_OWNER_EMAIL, role=UserRole.OWNER,
        )
        # Should NOT raise
        require_owner_or_admin(user)

    def test_non_owner_fails(self, db: SASession):
        """require_owner_or_admin raises for non-platform-owner email."""
        from app.services.invitation_service import require_owner_or_admin, InvitationError

        org, user = _create_org_and_user(
            db, email=f"other-{uuid.uuid4().hex[:8]}@t.com", role=UserRole.OWNER,
        )
        with pytest.raises(InvitationError) as exc_info:
            require_owner_or_admin(user)
        assert "platform owner" in str(exc_info.value).lower()
