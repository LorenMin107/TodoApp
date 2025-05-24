from .utils import *
from ..routers.auth.token_manager import get_db, SECRET_KEY, ALGORITHM, get_current_user, create_access_token
from ..routers.auth.login import authenticate_user
from jose import jwt
from datetime import timedelta
import pytest
from fastapi import HTTPException, Request
from unittest.mock import MagicMock

app.dependency_overrides[get_db] = override_get_db


def test_authenticate_user(test_user):
    db = TestingSessionLocal()

    authenticated_user = authenticate_user(test_user.username, 'test1234!', db)
    assert authenticated_user is not None
    assert authenticated_user.username == test_user.username

    non_existent_user = authenticate_user('nonexistent', 'wrongpassword', db)
    assert non_existent_user is False

    wrong_password_user = authenticate_user(test_user.username, 'wrongpassword', db)
    assert wrong_password_user is False


def test_create_access_token():
    username = 'testuser'
    user_id = 1
    role = 'user'
    expires_delta = timedelta(days=1)

    token, jti, expires = create_access_token(username, user_id, role, expires_delta)
    decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})

    assert decoded_token['sub'] == username
    assert decoded_token['id'] == user_id
    assert decoded_token['role'] == role


@pytest.mark.asyncio
async def test_get_current_user_valid_token():
    encode = {'sub': 'lorenmin', 'id': 1, 'role': 'admin', 'jti': '12345'}
    token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

    # Create a mock request object
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {"user-agent": "test-user-agent"}

    # Create a mock db session that returns None for is_token_revoked
    mock_db = MagicMock()
    mock_db.query.return_value.filter.return_value.first.return_value = None

    user = await get_current_user(request=mock_request, token=token, db=mock_db)
    assert user == {'username': 'lorenmin', 'id': 1, 'user_role': 'admin'}


@pytest.mark.asyncio
async def test_get_current_user_missing_payload():
    encode = {'role': 'user'}
    token = jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

    # Create a mock request object
    mock_request = MagicMock(spec=Request)
    mock_request.headers = {"user-agent": "test-user-agent"}

    # Create a mock db session
    mock_db = MagicMock()

    with pytest.raises(HTTPException) as excinfo:
        await get_current_user(request=mock_request, token=token, db=mock_db)

    assert excinfo.value.status_code == 401
    assert excinfo.value.detail == 'Invalid token'
