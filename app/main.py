# pylint: disable=no-name-in-module

from datetime import datetime, timedelta
from typing import Optional, List, Union
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
# database.initBase(database.SessionLocal())


pwd_context = CryptContext(schemes = ["bcrypt"], deprecated = "auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl = "tokens")

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origin_regex = r"(http.*localhost.*|https?:\/\/.*cardmatching.ovh.*)",
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
    if user == None:
        return None
    if user.access_level == "system":
        return None
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


@app.get("/v1/users", response_model = list)
async def return_all_users(current_user: models.User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)):
    return database.get_all_users(db)


@app.get("/v1/users/me", response_model = models.User)
async def read_my_data(current_user: models.User = Depends(get_current_user_from_token)):
    return current_user


@app.get("/v1/users/{user_id}", response_model = Union[models.User, List[Optional[models.User]]])
async def return_specific_user(current_user: models.User = Depends(get_current_user_from_token),
    user_id: str = Path(...),
    db: Session = Depends(get_db)):
    try:
        uid_int = int(user_id)
        ret = database.get_user_by_uid(db, uid_int)
        if ret == None:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail = "User with given ID not found",
            )
        return ret
    except ValueError:
        try:
            users = user_id.split(",")
            return [database.get_user_by_uid(db, int(i)) for i in users]
        except ValueError:
            raise HTTPException(
                status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail = "'user_id' must be either an integer or a list of comma-separated integers",
            )


@app.post("/v1/users", response_model = None)
async def create_new_user(user: models.UserNew, db: Session = Depends(get_db)):
    # check if username can be taken
    if user.username == "":
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail = "Username must not be empty"
        )
    if database.get_user_by_username(db, user.username) != None:
        raise HTTPException(
            status_code = status.HTTP_409_CONFLICT,
            detail = "Username already exists"
        )
    # check if password is not empty
    if user.password == "":
        raise HTTPException(
            status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail = "Password must not be empty"
        )
    # hash the password
    hashed_pass = get_password_hash(user.password)
    # save the user
    database.insert_new_user(db, user, hashed_pass)


@app.patch("/v1/users", response_model = None)
async def update_user_data(to_update: models.UserUpdate,
    current_user: models.User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)):
    # check password
    if to_update.password != None:
        if to_update.password == "":
            raise HTTPException(
                status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail = "Password must not be empty"
            )
        to_update.password = get_password_hash(to_update.password)
    database.update_user(db, current_user.uid, to_update.password, to_update.email,
        to_update.full_name)


@app.patch("/v1/users/{user_id}", response_model = None)
async def update_other_user_data(to_update: models.UserUpdate,
    user_id: int = Path(Ellipsis),
    current_user: models.User = Depends(get_current_user_from_token),
    db: Session = Depends(get_db)):
    # get user from DB
    modified_user = database.get_user_by_uid(db, user_id)
    if modified_user == None:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail = "User with given ID not found"
        )
    # check privilege
    if (modified_user.access_level == "system"
        or modified_user.access_level == "admin" and current_user.access_level != "system"
        or current_user.access_level not in ["system", "admin"]):
        raise HTTPException(
            status_code = status.HTTP_401_UNAUTHORIZED,
            detail = "Not authorized to update given user"
        )
    # check password
    if to_update.password != None:
        if to_update.password == "":
            raise HTTPException(
                status_code = status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail = "Password must not be empty"
            )
        to_update.password = get_password_hash(to_update.password)
    database.update_user(db, user_id, to_update.password, to_update.email,
        to_update.full_name)


@app.get("/health/live", response_model = str)
async def liveness_check():
    return "OK"


@app.get("/health/ready", response_model = dict)
async def readiness_check(db: Session = Depends(get_db)):
    if database.test_connection(db):
        return {
            "database": "OK"
        }
    else:
        raise HTTPException(
            status_code = status.HTTP_503_SERVICE_UNAVAILABLE,
            detail = "Database down",
        )



# za mejnik
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


@app.get("/v1/users/noauth", response_model = list)
async def return_all_users_noauth(db: Session = Depends(get_db)):
    return database.get_all_users(db)
