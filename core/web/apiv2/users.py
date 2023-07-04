from enum import Enum

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from core.schemas.user import UserSensitive, User
from core.web.apiv2.auth import GetCurrentUserWithPermissions

class SearchUserRequest(BaseModel):
    username: str
    count: int = 50
    page: int = 0

class SearchUserResponse(BaseModel):
    users: list[User]
    total: int

class ToggleableField(str, Enum):
    enabled = 'enabled'
    admin = 'admin'

class ToggleUserRequest(BaseModel):
    user_id: str
    field: ToggleableField

class ResetApiKeyRequest(BaseModel):
    user_id: str

class NewUserRequest(BaseModel):
    username: str
    password: str
    admin: bool

# API endpoints
router = APIRouter()

@router.post('/search')
async def search(request: SearchUserRequest) -> SearchUserResponse:
    """Searches for users."""
    request_args = request.dict(exclude={'count', 'page'})
    users, total = User.filter(request_args, offset=request.page, count=request.count)
    return SearchUserResponse(users=users, total=total)

@router.post('/toggle')
async def toggle(
    request: ToggleUserRequest,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True))) -> User:
    """Toggles a user's enabled or admin state."""
    if current_user.id == request.user_id:
        raise HTTPException(status_code=400, detail=f"cannot toggle own user ({current_user.username})")

    user = User.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")
    if request.field == ToggleableField.admin:
        user.admin = not user.admin
    elif request.field == ToggleableField.enabled:
        user.enabled = not user.enabled
    return user.save()

@router.post('/reset-api-key')
async def reset_api_key(
    request: ResetApiKeyRequest,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True))) -> User:
    """Resets a user's API key."""
    user = User.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")
    user.reset_api_key()
    return user.save()

@router.delete('/{user_id}')
async def delete(
    user_id: str,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True)) ) -> None:
    """Deletes a user from the database."""
    user = User.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f'user {user_id} not found')
    user.delete()

@router.post('/')
async def create(
    request: NewUserRequest,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True))) -> User:
    """Creates a new user."""
    user = UserSensitive(username=request.username, admin=request.admin)
    user.set_password(request.password)
    return user.save()
