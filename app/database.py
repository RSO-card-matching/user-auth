from typing import Optional
from os import getenv

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.exc import OperationalError

from . import models

db_ip = getenv("DATABASE_IP")
if db_ip:
    SQLALCHEMY_DATABASE_URL = db_ip
else:
    SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"

# engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args = {
    "connect_timeout": 1
})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# temporary, for testing
def initBase(db: Session):
    engine = db.get_bind()
    try:
        models.UserModel.__table__.drop(engine)
    except:
        pass
    models.UserModel.__table__.create(engine)
    db_users = [models.UserModel(
        uid = 0,
        username = "system",
        access_level = "system",
        full_name = "",
        email = "",
        hashed_password = ""
    ),
    models.UserModel(
        uid = 1,
        username = "ana",
        access_level = "admin",
        full_name = "Ana Agrež",
        email = "ana.agrez@example.com",
        hashed_password = "$2b$12$kUnbsxhy3ns9e0d//MWxQuKYphkusjav6NBwqX/lK2QlY7Yzt8sHS"  # "njah"
    ),
    models.UserModel(
        uid = 2,
        username = "berta",
        access_level = "user",
        full_name = "Berta Bohak",
        email = "berta.bohak@example.com",
        hashed_password = "$2b$12$i14mgMTbkf.O22Qnkz6AfOAJ9xendDRTOHEc8ey90Z9QQfwSOuy6."  # "njeh"
    ),
    models.UserModel(
        uid = 3,
        username = "cilka",
        access_level = "user",
        full_name = "Cilka Cijan",
        email = "cilka.cijan@example.com",
        hashed_password = "$2b$12$hGUiErRdzwdD3LdCd0Ugj.16lawsxJas2hO0.P/MI0NdSXGkAYJ06"  # "njoh"
    )]
    db.add_all(db_users)
    db.commit()
    db.close()


def get_user_by_uid_sensitive(db: Session, uid: int) -> Optional[models.UserSensitive]:
    user = db.query(models.UserModel).filter(models.UserModel.uid == uid).first()
    if user:
        return models.UserSensitive(**user.__dict__)
    return None


def get_user_by_uid(db: Session, uid: int) -> Optional[models.UserSensitive]:
    user = db.query(models.UserModel).filter(models.UserModel.uid == uid).first()
    if user:
        return models.User(**user.__dict__)
    return None


def get_user_by_username_sensitive(db: Session, username: str) -> Optional[models.UserSensitive]:
    user = db.query(models.UserModel).filter(models.UserModel.username == username).first()
    if user:
        return models.UserSensitive(**user.__dict__)
    return None


def get_user_by_username(db: Session, username: str) -> Optional[models.UserSensitive]:
    user = db.query(models.UserModel).filter(models.UserModel.username == username).first()
    if user:
        return models.User(**user.__dict__)
    return None


def get_all_users(db: Session) -> list:
    return [models.User(**u.__dict__) for u in db.query(models.UserModel).all()]


def insert_new_user(db: Session, new_user: models.UserNew, hashed_pass: str) -> None:
    new_id = db.query(models.UserModel).count()
    user_model = models.UserModel(
        uid = new_id,
        username = new_user.username,
        access_level = "user",
        full_name = new_user.full_name,
        email = new_user.email,
        hashed_password = hashed_pass
    )
    db.add(user_model)
    db.commit()


def update_user(db: Session, uid: int, pass_hash: Optional[str],
    email: Optional[str], full_name: Optional[str]) -> None:
    user = db.query(models.UserModel).filter(models.UserModel.uid == uid).first()
    if pass_hash != None:
        user.hashed_password = pass_hash
    if email != None:
        user.email = email
    if full_name != None:
        user.full_name = full_name
    db.commit()


def test_connection(db: Session) -> bool:
    try:
        db.query(models.UserModel).first()
        return True
    except OperationalError:
        return False
