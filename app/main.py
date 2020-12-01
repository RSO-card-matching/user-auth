# pylint: disable=no-name-in-module

from datetime import datetime, timedelta
from typing import Optional
from os import getenv

from fastapi import Depends, FastAPI, Form, HTTPException, Path, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models, database

SECRET_KEY = getenv("OAUTH_SIGN_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

if (SECRET_KEY == None):
    print("Please define OAuth signing key!")
    exit(-1)

# fastAPI dependecy magic
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# init testing DB
database.initBase(database.SessionLocal())


pwd_context = CryptContext(schemes = ["bcrypt"], deprecated = "auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "tokens")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex = r"http:\/\/localhost:.*",
    allow_credentials = True,
    allow_methods = ["*"],
    allow_headers = ["*"],
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> bool:
    return pwd_context.hash(password)


def authenticate_user(db: Session, username: str, password: str) -> Optional[models.UserSensitive]:
    user = database.get_user_by_username_sensitive(db, username)
    if not verify_password(password, user.hashed_password):
        return None
    return models.UserSensitive(**user.__dict__)


def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm = ALGORITHM)
    return encoded_jwt


async def get_current_user_from_token(token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)) -> models.User:
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
        token_data = models.TokenData(uid = uid)
    except JWTError:
        raise credentials_exception
    user = database.get_user_by_uid(db, token_data.uid)
    if user is None:
        raise credentials_exception
    return user


def get_user_from_token(db: Session, token: str) -> models.User:
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
        token_data = models.TokenData(uid = uid)
    except JWTError:
        raise credentials_exception
    user = database.get_user_by_uid(db, token_data.uid)
    if user is None:
        raise credentials_exception
    return user



@app.post("/tokens", response_model = models.Token)
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


# @app.post("/user", response_model = models.User)
# async def read_token_data(token: str = Form(...),
#     current_user: models.User = Depends(get_current_user_from_token)):
#     db = database.SessionLocal()
#     try:
#         return get_user_from_token(db, token)
#     except HTTPException:
#         raise HTTPException(
#             status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
#             detail = "Invalid token",
#         )
#     finally:
#         db.close()


@app.get("/v1/users", response_model = list)
async def return_all_users(current_user: models.User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)):
    return database.get_all_users(db)


@app.get("/v1/users/noauth", response_model = list)
async def return_all_users_noauth(db: Session = Depends(get_db)):
    return database.get_all_users(db)


@app.get("/v1/users/me", response_model = models.User)
async def read_my_data(current_user: models.User = Depends(get_current_user_from_token)):
    return current_user


@app.get("/v1/users/{user_id}", response_model = dict)
async def return_specific_user(current_user: models.User = Depends(get_current_user_from_token),
    user_id: int = Path(...),
    db: Session = Depends(get_db)):
    return database.get_user_by_uid(db, user_id)


@app.get("/health/live", response_model = str)
async def liveness_check():
    return "OK"


@app.get("/health/ready", response_model = str)
async def readiness_check():
    return "OK"  # TODO: čekiranje baze or sth?


@app.get("/demo", response_model = dict)
async def mejnik_demo():
    return {
        "clani": [
            "br4754",
            "jz4314"
        ],
        "opis_projekta": "Nas projekt implementira aplikacijo za trgovanje z zbirateljskimi kartami.",
        "mikrostoritve": [
            f"{getenv('CARDDATA_IP')}/v1/cards/noauth",
            f"{getenv('USERAUTH_IP')}/v1/users/noauth"
        ],
        "github": [
            "https://github.com/RSO-card-matching/card-data",
            "https://github.com/RSO-card-matching/user-auth"
        ],
        "travis": [],
        "dockerhub": [
            "https://hub.docker.com/r/cardmatching/card-data",
            "https://hub.docker.com/r/cardmatching/user-auth"
        ]
    }
