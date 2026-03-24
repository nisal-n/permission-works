import os

class Config:
    SECRET_KEY = os.environ.get("APP_SECRET_KEY", "change-this-secret-key")  # replace for real use

    # IFS / OAuth
    TOKEN_URL = "https://pyse8ne-dev1.build.ifs.cloud/auth/realms/pyse8nedev1/protocol/openid-connect/token"
    CLIENT_ID = "IFS_boomi"
    CLIENT_SECRET = "Epfw6gkrGV1S0XRfPpz2"
    SCOPE = "openid microprofile-jwt"


    # ===================== CFG tenant (target) =====================
    # Projection base for CFG
    CFG_BASE = os.environ.get("CFG_BASE", "https://aagl-cfg.ifs.cloud/main/ifsapplications/projection/v1")

    # Discovery inputs (recommended)
    CFG_ISSUER_ROOT = os.environ.get("CFG_ISSUER_ROOT", "https://aagl-cfg.ifs.cloud")
    CFG_REALM = os.environ.get("CFG_REALM", "aaglcfg1")  # << set real realm (e.g., "ifs", "prod", etc.)

    # Service client credentials in CFG tenant
    CFG_CLIENT_ID = os.environ.get("CFG_CLIENT_ID", "IFS_boomi")
    CFG_CLIENT_SECRET = os.environ.get("CFG_CLIENT_SECRET", "Bi3yHUf2LvUK79HBYW0n")
    CFG_SCOPE = os.environ.get("CFG_SCOPE", "openid microprofile-jwt")

    # TLS verification for outbound HTTPS
    # True (default), False, or path to CA bundle (e.g., "/etc/ssl/certs/ca-bundle.crt")
    CFG_SSL_VERIFY = os.environ.get("CFG_SSL_VERIFY", "true").lower() not in ("0", "false", "no")

    # OData base (FndTempLobs lives here)
    CFG_ODATA_BASE = os.environ.get("CFG_ODATA_BASE", "https://aagl-cfg.ifs.cloud/main/ifsapplications/odata/v1")
    CFG_ODATA_PREFIX = os.environ.get("CFG_ODATA_PREFIX", "ifsfoundation")

    CFG_IMPORT_MODE = os.environ.get("CFG_IMPORT_MODE", "xml")  # "xml" or "zip"

    # IFS endpoints
    BASE = "https://pyse8ne-dev1.build.ifs.cloud/main/ifsapplications/projection/v1"
    PERMISSION_SET_URL = f"{BASE}/PermissionSetHandling.svc/PermissionSets"
    GRANT_PROJECTION_URL = f"{BASE}/PermissionSetHandling.svc/GrantProjections"
    GRANT_LOBBY_PAGE_URL = f"{BASE}/PermissionSetHandling.svc/GrantLobbyPage"
    GRANT_USERS_URL = f"{BASE}/PermissionSetHandling.svc/GrantUsers"
    USERS_URL = f"{BASE}/PermissionSetHandling.svc/Users?$top=500"
    USERS_BASE_URL = f"{BASE}/PermissionSetHandling.svc/Users"
    USER_GROUPS_BASE_URL = f"{BASE}/PermissionSetHandling.svc/UserGroups"
    GRANT_GROUPS_URL = f"{BASE}/PermissionSetHandling.svc/GrantGroups"
    GRANT_BPAS_URL = f"{BASE}/PermissionSetHandling.svc/GrantBpas"
    PERMISSION_SETS_BASE_URL = f"{BASE}/PermissionSetHandling.svc/PermissionSets"
