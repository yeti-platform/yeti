import datetime
import json

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, HTTPException, Response, Security, status
from fastapi.responses import RedirectResponse
from fastapi.security import (
    APIKeyCookie,
    APIKeyHeader,
    OAuth2PasswordBearer,
    OAuth2PasswordRequestForm,
)
from google.auth import exceptions as google_exceptions
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token as google_oauth_id_token
from jose import JWTError, jwt
from starlette.requests import Request

from core.config.config import yeti_config
from core.schemas.user import User, UserSensitive, create_access_token

ACCESS_TOKEN_EXPIRE_DELTA = datetime.timedelta(
    minutes=yeti_config.get("auth", "access_token_expire_minutes", default=30)
)
BROWSER_TOKEN_EXPIRE_DELTA = datetime.timedelta(
    minutes=yeti_config.get("auth", "browser_token_expire_minutes", default=43200)
)
SECRET_KEY = yeti_config.get("auth", "secret_key")
if not SECRET_KEY:
    raise RuntimeError("You must set auth.secret_key in the configuration file.")

ALGORITHM = yeti_config.get("auth", "algorithm")
YETI_AUTH = yeti_config.get("auth", "enabled")
YETI_WEBROOT = yeti_config.get("system", "webroot")

AUTH_MODULE = yeti_config.get("auth", "module")

if AUTH_MODULE == "oidc":
    if (
        not yeti_config.get("auth", "oidc_client_id")
        or not yeti_config.get("auth", "oidc_client_secret")
        or not yeti_config.get("auth", "oidc_discovery_url")
    ):
        raise Exception(
            "OIDC AUTHENTICATION requires OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_DISCOVERY_URL to be set in the configuration file"
        )

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v2/auth/token", auto_error=False)
cookie_scheme = APIKeyCookie(name="yeti_session", auto_error=False)
api_key_header = APIKeyHeader(name="x-yeti-apikey")


def get_oauth_client() -> OAuth:
    client_id = yeti_config.get("auth", "oidc_client_id")
    client_secret = yeti_config.get("auth", "oidc_client_secret")
    discovery_url = yeti_config.get("auth", "oidc_discovery_url")

    client = OAuth()
    client.register(
        name="oidc",
        server_metadata_url=discovery_url,
        client_kwargs={
            "scope": "openid email profile",
        },
        client_id=client_id,
        client_secret=client_secret,
    )
    return client


def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    cookie: str = Security(cookie_scheme),
) -> UserSensitive:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    request.state.username = None
    request.state.user = None
    if not token and not cookie:
        raise credentials_exception

    token = token or cookie

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = UserSensitive.find(username=username)
    if user is None:
        raise credentials_exception
    request.state.username = user.username
    request.state.user = user
    return user


def get_current_active_user(current_user: User = Security(get_current_user)):
    if not current_user.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account disabled. Please contact your server admin.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user


class GetCurrentUserWithPermissions:
    """Helper class to manage a layer of user permissions.

    In routes, use as:
        user: User = Depends(GetCurrentUserWithPermissions(admin=True))
    """

    def __init__(self, admin: bool):
        self.admin = admin

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        if not user.admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"user {user.username} is not an admin",
            )
        return user


# API Endpoints
router = APIRouter()

# We only want certain endpoints to be defined depending on the auth module.
if AUTH_MODULE == "oidc":

    @router.get("/oidc-login")
    async def login_info(request: Request):
        redirect_uri = request.url_for("oidc_callback")
        if YETI_WEBROOT:
            scheme, netloc = YETI_WEBROOT.split("://")
            redirect_uri = redirect_uri.replace(netloc=netloc, scheme=scheme)
        try:
            return await get_oauth_client().oidc.authorize_redirect(
                request, redirect_uri
            )
        except OAuthError:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error while authenticating with upstream OIDC provider. Please contact your server admin.",
            )

    @router.get("/oidc-callback", response_class=RedirectResponse)
    async def oidc_callback(request: Request) -> RedirectResponse:
        try:
            token = await get_oauth_client().oidc.authorize_access_token(request)
        except OAuthError:
            return RedirectResponse(url="/")

        username = token["userinfo"]["email"]
        db_user = User.find(username=username)
        if not db_user:
            db_user = User(username=username, admin=False, enabled=False)
            db_user.save()
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account disabled. Please contact your server admin.",
            )

        access_token = create_access_token(
            data={"sub": db_user.username, "enabled": db_user.enabled},
            expires_delta=BROWSER_TOKEN_EXPIRE_DELTA,
        )
        response = RedirectResponse(url="/")
        response.set_cookie(
            key="yeti_session",
            value=access_token,
            httponly=True,
            secure=True,
            max_age=int(BROWSER_TOKEN_EXPIRE_DELTA.total_seconds()),
        )
        return response

    @router.post("/oidc-callback-token")
    async def oidc_api_callback(request: Request):
        try:
            req_body = await request.body()
            id_token = json.loads(req_body)["id_token"]
            idinfo = google_oauth_id_token.verify_oauth2_token(
                id_token, google_requests.Request()
            )
        except (google_exceptions.GoogleAuthError, ValueError, KeyError) as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token provided: {error}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        audience_client_ids = set(
            yeti_config.get("auth", "oidc_extra_client_audiences", "").split(",")
        )
        audience_client_ids.add(yeti_config.get("auth", "oidc_client_id"))

        if idinfo["aud"] not in audience_client_ids:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is not intended for this application (audience mismatch)",
                headers={"WWW-Authenticate": "Bearer"},
            )

        user = UserSensitive.find(username=idinfo["email"])
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid user. Please contact your server admin.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.enabled:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account disabled. Please contact your server admin.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        access_token = create_access_token(
            data={"sub": user.username, "enabled": user.enabled},
            expires_delta=ACCESS_TOKEN_EXPIRE_DELTA,
        )
        return {"access_token": access_token, "token_type": "bearer"}


# We only want certain endpoints to be defined depending on the auth module.
if AUTH_MODULE == "local":

    @router.post("/token")
    def login(
        response: Response, form_data: OAuth2PasswordRequestForm = Depends()
    ) -> dict[str, str]:
        if not YETI_AUTH:
            user = UserSensitive.find(username="yeti")
            if not user:
                user = UserSensitive(username="yeti", admin=True)
                user.set_password("yeti")
                user.save()
        else:
            user = UserSensitive.find(username=form_data.username)
            if not (user and user.verify_password(form_data.password)):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Incorrect username or password",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            if not user.enabled:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account disabled. Please contact your server admin.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

        access_token = create_access_token(
            data={"sub": user.username, "enabled": user.enabled},
            expires_delta=BROWSER_TOKEN_EXPIRE_DELTA,
        )
        response.set_cookie(key="yeti_session", value=access_token, httponly=True)
        return {"access_token": access_token, "token_type": "bearer"}


@router.post("/api-token")
def login_api(x_yeti_api_key_token: str = Security(api_key_header)) -> dict[str, str]:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "x-yeti-apikey"},
    )

    try:
        payload = jwt.decode(
            x_yeti_api_key_token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            options={"verify_exp": False, "requires_exp": False},
        )
    except JWTError:
        raise credentials_exception

    user = UserSensitive.find(username=payload.get("sub"))
    if not user:
        raise credentials_exception

    try:
        user.validate_api_key_payload(payload)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
            headers={"WWW-Authenticate": "x-yeti-apikey"},
        )

    if not user.enabled:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account disabled. Please contact your server admin.",
            headers={"WWW-Authenticate": "x-yeti-apikey"},
        )

    access_token = create_access_token(
        data={"sub": user.username, "enabled": user.enabled},
        expires_delta=ACCESS_TOKEN_EXPIRE_DELTA,
    )
    user.api_keys[payload["name"]].last_used = datetime.datetime.now(
        tz=datetime.timezone.utc
    )
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/me")
def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user


@router.post("/logout")
async def logout(response: Response) -> dict[str, str]:
    response.delete_cookie(key="yeti_session")
    return {"message": "Logged out"}
