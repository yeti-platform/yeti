import datetime
from enum import Enum

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, ConfigDict

from core.schemas import rbac, roles
from core.schemas.user import RegisteredApiKey, User, UserSensitive
from core.web.apiv2.auth import GetCurrentUserWithPermissions, get_current_user


class SearchUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    count: int = 50
    page: int = 0


class UserDetailsResponse(BaseModel):
    user: User
    groups: list[rbac.Group]


class SearchUserResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    users: list[User]
    total: int


class ToggleableField(str, Enum):
    enabled = "enabled"
    admin = "admin"


class ToggleUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    field: ToggleableField


class PatchRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    role: roles.Permission


class NewApiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    name: str
    scopes: list[str] = []
    expiration: datetime.timedelta | None = None


class NewAPIKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    token: str
    api_keys: dict[str, RegisteredApiKey]


class DeleteApiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    name: str


class DeleteApiKeyResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_keys: dict[str, RegisteredApiKey]


class ToggleApiKeyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    name: str


class ResetPasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str
    new_password: str


class NewUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str
    password: str
    admin: bool


class UpdateUserRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: str


# API endpoints
router = APIRouter()


@router.get("/{user_id}")
def get(httpreq: Request, user_id: str) -> UserDetailsResponse:
    """Gets a user by ID."""
    if httpreq.state.user.id != user_id and not httpreq.state.user.admin:
        raise HTTPException(
            status_code=403, detail="cannot view details for other users"
        )
    user = UserSensitive.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"user {user_id} not found")

    groups = user.get_groups()
    return UserDetailsResponse(user=user, groups=groups)


@router.post("/search")
def search(request: SearchUserRequest) -> SearchUserResponse:
    """Searches for users."""
    request_args = request.model_dump(exclude={"count", "page"})
    users, total = UserSensitive.filter(
        request_args, offset=request.page, count=request.count
    )
    return SearchUserResponse(users=users, total=total)


@router.post("/toggle")
def toggle(
    request: ToggleUserRequest,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True)),
) -> User:
    """Toggles a user's enabled or admin state."""
    if current_user.id == request.user_id:
        raise HTTPException(
            status_code=400, detail=f"cannot toggle own user ({current_user.username})"
        )

    user = UserSensitive.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")
    if request.field == ToggleableField.admin:
        user.admin = not user.admin
    elif request.field == ToggleableField.enabled:
        user.enabled = not user.enabled
    return user.save()


@router.patch("/role")
def update_user_role(
    request: PatchRoleRequest,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True)),
) -> User:
    """Updates a user's profile - only the role for now."""
    user = UserSensitive.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"user {request.user_id} not found")
    user.global_role = request.role
    return user.save()


@router.post("/new-api-key")
def new_api_key(
    request: NewApiKeyRequest, current_user: UserSensitive = Depends(get_current_user)
) -> NewAPIKeyResponse:
    if not current_user.admin and current_user.id != request.user_id:
        raise HTTPException(
            status_code=401, detail="cannot create API keys for other users"
        )

    user = UserSensitive.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")

    token = user.create_api_key(
        request.name, scopes=request.scopes, expiration_delta=request.expiration
    )
    user.save()
    return NewAPIKeyResponse(name=request.name, token=token, api_keys=user.api_keys)


@router.post("/toggle-api-key")
def toggle_api_key(
    request: ToggleApiKeyRequest,
    current_user: UserSensitive = Depends(get_current_user),
) -> RegisteredApiKey:
    if not current_user.admin and current_user.id != request.user_id:
        raise HTTPException(
            status_code=401, detail="cannot create API keys for other users"
        )

    user = UserSensitive.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")

    assert isinstance(user.api_keys, dict)
    if request.name not in user.api_keys:
        raise HTTPException(
            status_code=401, detail=f"{request.name}: invalid API key name"
        )

    user.api_keys[request.name].enabled = not user.api_keys[request.name].enabled
    user.save()
    return user.api_keys[request.name]


@router.post("/delete-api-key")
def reset_api_key(
    request: DeleteApiKeyRequest,
    current_user: UserSensitive = Depends(get_current_user),
) -> DeleteApiKeyResponse:
    """Resets a user's API key."""
    if not current_user.admin and current_user.id != request.user_id:
        raise HTTPException(
            status_code=401, detail="cannot delete API keys for other users"
        )

    user = UserSensitive.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")

    if request.name not in user.api_keys:
        raise HTTPException(
            status_code=401, detail=f"{request.name}: invalid API key name"
        )
    user.delete_api_key(request.name)

    return DeleteApiKeyResponse(api_keys=user.api_keys)


@router.post("/reset-password")
def reset_password(
    request: ResetPasswordRequest,
    current_user: UserSensitive = Depends(get_current_user),
) -> User:
    """Resets a user's password."""
    # Only move forward if the current user is an admin or the target user
    if not current_user.admin and current_user.id != request.user_id:
        raise HTTPException(
            status_code=401, detail="cannot reset password for other users"
        )

    user = UserSensitive.get(request.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user {user_id} not found")

    user.set_password(request.new_password)
    return user.save()


@router.delete("/{user_id}")
def delete(
    user_id: str,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True)),
) -> None:
    """Deletes a user from the database."""
    user = UserSensitive.get(user_id)
    if not user:
        raise HTTPException(status_code=404, detail=f"user {user_id} not found")
    user.delete()


@router.post("/")
def create(
    request: NewUserRequest,
    current_user: User = Depends(GetCurrentUserWithPermissions(admin=True)),
) -> User:
    """Creates a new user."""
    user = UserSensitive(username=request.username, admin=request.admin)
    user.set_password(request.password)
    user = user.save()

    all_users = rbac.Group.find(name="All users")
    if not all_users:
        all_users = rbac.Group(name="All users").save()
    if not request.admin:
        user.link_to_acl(all_users, roles.Role.READER)
    else:
        admins = rbac.Group.find(name="Admins")
        if not admins:
            admins = rbac.Group(name="Admins").save()
        user.link_to_acl(admins, roles.Role.OWNER)
        user.link_to_acl(all_users, roles.Role.OWNER)

    return user
