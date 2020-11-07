# pylint: disable=no-name-in-module

from datetime import datetime, timedelta
from typing import Optional
from os import getenv

from fastapi import Depends, FastAPI, Form, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from .models import Token, TokenData, User, UserSensitive
from .database import SessionLocal, get_user_by_uid, get_user_by_uid_sensitive
from .database import initBase, get_user_by_username, get_user_by_username_sensitive
from .database import get_all_users

# TODO: zamenjaj to s skrito spremenljivko, ki se prilepi med buildanjem
# SECRET_KEY = "9f86047690f11729af7c37eac5cb75d30ca597af7d145407664a82c7cb81915c"
SECRET_KEY = getenv("OAUTH_SIGN_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if (SECRET_KEY == None):
    print("Please define OAuth signing key!")
    exit(-1)

# fastAPI dependecy magic
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# init testing DB
initBase(SessionLocal())

# # placeholder, za zamenjati s produkcijsko bazo
# fake_users_db = {
#     0: {
#         "username": "ana",
#         "uid": 0,
#         "access_level": "admin",
#         "full_name": "Ana Agrež",
#         "email": "ana.agrez@example.com",
#         "hashed_password": "$2b$12$kUnbsxhy3ns9e0d//MWxQuKYphkusjav6NBwqX/lK2QlY7Yzt8sHS"  # "njah"
#     },
#     1: {
#         "username": "berta",
#         "uid": 1,
#         "access_level": "user",
#         "full_name": "Berta Bohak",
#         "email": "berta.bohak@example.com",
#         "hashed_password": "$2b$12$i14mgMTbkf.O22Qnkz6AfOAJ9xendDRTOHEc8ey90Z9QQfwSOuy6."  # "njeh"
#     },
#     2: {
#         "username": "cilka",
#         "uid": 2,
#         "access_level": "user",
#         "full_name": "Cilka Cijan",
#         "email": "cilka.cijan@example.com",
#         "hashed_password": "$2b$12$hGUiErRdzwdD3LdCd0Ugj.16lawsxJas2hO0.P/MI0NdSXGkAYJ06"  # "njoh"
#     }
# }

# # placeholder, za zamenjati s produkcijsko bazo
# uname_to_id = {
#     "ana": 0,
#     "berta": 1,
#     "cilka": 2
# }


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="request_token")

app = FastAPI()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> bool:
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str) -> Optional[UserSensitive]:
    user = get_user_by_username_sensitive(db, username)
    if not verify_password(password, user.hashed_password):
        return None
    return UserSensitive(**user.__dict__)


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encoded_jwt


async def get_current_user_from_token(token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials",
        headers = {"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        uid: Optional[int] = int(payload.get("sub"))
        if uid is None:
            raise credentials_exception
        token_data = TokenData(uid = uid)
    except JWTError:
        raise credentials_exception
    user = get_user_by_uid(db, token_data.uid)
    if user is None:
        raise credentials_exception
    return user


def get_user_from_token(db: Session, token: str) -> User:
    credentials_exception = HTTPException(
        status_code = status.HTTP_401_UNAUTHORIZED,
        detail = "Could not validate credentials",
        headers = {"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms = [ALGORITHM])
        uid: Optional[int] = int(payload.get("sub"))
        if uid is None:
            raise credentials_exception
        token_data = TokenData(uid = uid)
    except JWTError:
        raise credentials_exception
    user = get_user_by_uid(db, token_data.uid)
    if user is None:
        raise credentials_exception
    return user



@app.post("/request_token", response_model = Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Incorrect username or password",
            headers = {"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes = ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data = {"sub": str(user.uid)},
        expires_delta = access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/me", response_model = User)
async def read_my_data(current_user: User = Depends(get_current_user_from_token)):
    return current_user


@app.post("/user", response_model = User)
async def read_token_data(token: str = Form(...),
    current_user: User = Depends(get_current_user_from_token)):
    db = SessionLocal()
    try:
        return get_user_from_token(db, token)
    except HTTPException:
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail = "Invalid token",
        )
    finally:
        db.close()

@app.get("/all_users", response_model = dict)
async def return_all_users(current_user: User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)):
    return get_all_users(db)
