import datetime
import json
import logging
from typing import Any

import httpx
import jwt
from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, Depends, HTTPException, Response, Security, status
from fastapi.concurrency import run_in_threadpool
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
from pydantic import BaseModel
from starlette.requests import Request

from core.config.config import yeti_config
from core.schemas.user import User, UserSensitive, create_access_token

logger = logging.getLogger(__name__)

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

# OAuth client IDs whose Google access tokens can be exchanged for API tokens
# at /api/v2/auth/google-access-token, matched against the "azp" claim reported
# by Google's tokeninfo endpoint. The exchange endpoint is only registered when
# this is set and the server uses OIDC authentication.
GOOGLE_ACCESS_TOKEN_CLIENT_IDS = frozenset(
    client_id.strip()
    for client_id in str(
        yeti_config.get("auth", "google_access_token_client_ids", default="") or ""
    ).split(",")
    if client_id.strip()
)
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"
# tokeninfo is a single round trip to Google. If Google is slow, failing fast
# beats waiting: clients retry on the resulting 503.
GOOGLE_TOKENINFO_TIMEOUT_SECONDS = 3
# Loading CA certificates takes milliseconds of CPU on the event loop, so
# tokeninfo requests share one SSL context instead of each loading their own.
GOOGLE_TOKENINFO_SSL_CONTEXT = httpx.create_ssl_context()
# Scopes that only reveal who the token holder is. Exchanged tokens must not
# carry any other scope: a token that can also call other APIs was minted for
# another purpose, and accepting it widens the set of tokens that could be
# replayed against Yeti.
IDENTITY_SCOPES = frozenset(
    {
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
    }
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
    except jwt.PyJWTError:
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


def _api_session_for(username: str) -> dict[str, str]:
    """Returns an API session token for an existing, enabled user.

    Raises:
        HTTPException: 401 if the user doesn't exist or is disabled.
    """
    user = UserSensitive.find(username=username)
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


def _invalid_token_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid token provided",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _get_google_tokeninfo(access_token: str) -> dict[str, Any]:
    """Asks Google which identity, client and scopes an access token is for.

    Raises:
        HTTPException: 401 if Google doesn't recognize the token, 503 if Google
            can't be reached in time or answers with an error.
    """
    unavailable = HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Could not validate the token, try again later.",
    )
    try:
        async with httpx.AsyncClient(
            timeout=GOOGLE_TOKENINFO_TIMEOUT_SECONDS,
            verify=GOOGLE_TOKENINFO_SSL_CONTEXT,
        ) as http_client:
            # A form body keeps the token out of URLs, which tend to be logged.
            response = await http_client.post(
                GOOGLE_TOKENINFO_URL, data={"access_token": access_token}
            )
    except httpx.HTTPError:
        raise unavailable from None

    if response.status_code >= 500:
        raise unavailable
    if response.status_code != 200:
        raise _invalid_token_error()
    try:
        tokeninfo = response.json()
    except ValueError:
        raise unavailable from None
    if not isinstance(tokeninfo, dict):
        raise unavailable
    return tokeninfo


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

        return _api_session_for(idinfo["email"])


class AccessTokenExchangeRequest(BaseModel):
    access_token: str


async def google_access_token(body: AccessTokenExchangeRequest) -> dict[str, str]:
    """Exchanges a Google OAuth access token for an API session token.

    The access token must have been issued to one of the OAuth clients in
    `auth.google_access_token_client_ids`, carry only identity scopes (openid,
    email, profile), and belong to the verified email address of an existing,
    enabled user. This serves API clients that can mint Google access tokens
    without a browser but can't get ID tokens.

    Only available when the server uses OIDC authentication and that setting is
    set. See yeti.conf.sample for which OAuth clients are safe to list.
    """
    # Google's tokeninfo endpoint resolves the token. The OIDC userinfo endpoint
    # can't replace it: userinfo doesn't report which client a token was issued
    # to, so tokens issued to any application would be accepted.
    tokeninfo = await _get_google_tokeninfo(body.access_token)
    client_id = tokeninfo.get("azp")
    email = tokeninfo.get("email")
    if client_id not in GOOGLE_ACCESS_TOKEN_CLIENT_IDS:
        logger.info(
            "Rejected access token for %s: client %s is not allowed", email, client_id
        )
        raise _invalid_token_error()

    scopes = set(str(tokeninfo.get("scope", "")).split())
    if not scopes or not scopes <= IDENTITY_SCOPES:
        logger.info(
            "Rejected access token for %s: scopes %s are not identity scopes",
            email,
            sorted(scopes - IDENTITY_SCOPES),
        )
        raise _invalid_token_error()

    if not email or str(tokeninfo.get("email_verified")).lower() != "true":
        logger.info(
            "Rejected access token for %s: email address missing or not verified",
            email,
        )
        raise _invalid_token_error()

    # The user lookup blocks on the database, so it runs in the threadpool. The
    # tokeninfo call above holds no threadpool slot while it waits for Google.
    return await run_in_threadpool(_api_session_for, email)


# Registered only when configured, like the OIDC routes, so that other
# deployments neither serve the route nor list it in their API schema.
if AUTH_MODULE == "oidc" and GOOGLE_ACCESS_TOKEN_CLIENT_IDS:
    router.add_api_route("/google-access-token", google_access_token, methods=["POST"])


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
            options={"verify_exp": False},
        )
    except jwt.PyJWTError:
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
    # validate_api_key_payload above guarantees the key exists in api_keys.
    assert user.api_keys is not None
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
