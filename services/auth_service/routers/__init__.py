"""Auth service route modules — extracted from monolithic main.py."""

from fastapi import APIRouter

router = APIRouter()

# Sub-routers for each domain
auth_router = APIRouter(prefix="/auth", tags=["auth"])
user_router = APIRouter(prefix="/auth", tags=["users"])
admin_router = APIRouter(prefix="/auth/admin", tags=["admin"])
org_router = APIRouter(prefix="/auth", tags=["organizations"])
oauth_router = APIRouter(prefix="/auth", tags=["oauth"])
mfa_router = APIRouter(prefix="/auth", tags=["mfa"])
apikey_router = APIRouter(prefix="/auth", tags=["api-keys"])
session_router = APIRouter(prefix="/auth", tags=["sessions"])
rbac_router = APIRouter(prefix="/auth/rbac", tags=["rbac"])
billing_router = APIRouter(prefix="/auth", tags=["billing"])
security_router = APIRouter(prefix="/auth", tags=["security"])
compliance_router = APIRouter(prefix="/auth", tags=["compliance"])
settings_router = APIRouter(prefix="/auth", tags=["settings"])
gdpr_router = APIRouter(prefix="/auth/gdpr", tags=["gdpr"])
