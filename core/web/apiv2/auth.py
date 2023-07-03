import datetime

from fastapi import APIRouter, Depends, HTTPException, Security, Response
from fastapi import status
from fastapi.security import APIKeyHeader, APIKeyCookie, OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt

from core.config.config import yeti_config
from core.schemas.user import User, UserSensitive

ACCESS_TOKEN_EXPIRE_MINUTES = datetime.timedelta(
    minutes=yeti_config.auth['access_token_expire_minutes'])
SECRET_KEY = yeti_config.auth['secret_key']
ALGORITHM = yeti_config.auth['algorithm']
YETI_AUTH = yeti_config.auth['enabled']

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v2/auth/token", auto_error=False)
cookie_scheme = APIKeyCookie(name="yeti_session", auto_error=False)
api_key_header = APIKeyHeader(name="x-yeti-apikey")

def create_access_token(data: dict, expires_delta: datetime.timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.utcnow() + expires_delta
    else:
        expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), cookie: str = Security(cookie_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

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

    user = User.find(username=username)
    if user is None:
        raise credentials_exception
    return user

class GetCurrentUserWithPermissions:
    """Helper class to manage a layer of user permissions.

    In routes, use as:
        user: User = Depends(GetCurrentUserWithPermissions(admin=True))
    """
    def __init__(self, admin: bool):
        self.admin = admin

    async def __call__(self, user: User = Depends(get_current_user)) -> User:
        if not user.admin:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"user {user.username} is not an admin",
            )
        return user

# API Endpoints
router = APIRouter()

@router.post("/token")
async def login(response: Response, form_data: OAuth2PasswordRequestForm = Depends()):

    if not YETI_AUTH:
        user = UserSensitive.find(username='yeti')
        if not user:
            user = UserSensitive(username='yeti', admin=True).save()
    else:
        user = UserSensitive.find(username=form_data.username)
        if not (user and user.verify_password(form_data.password)):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )

    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    response.set_cookie(key="yeti_session", value=access_token, httponly=True)
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/api-token")
async def login_api(x_yeti_api_key: str = Security(api_key_header)):
    user = UserSensitive.find(api_key=x_yeti_api_key)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=ACCESS_TOKEN_EXPIRE_MINUTES
    )
    return {"access_token": access_token, "token_type": "bearer"}

@router.get("/me")
async def me(current_user: User = Depends(get_current_user)) -> User:
    return current_user
