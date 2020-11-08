from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from . import models


SQLALCHEMY_DATABASE_URL = "sqlite:///./sql_app.db"
# SQLALCHEMY_DATABASE_URL = "postgresql://user:password@postgresserver/db"
# TODO: make selection using environment vars

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
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
        username = "ana",
        access_level = "admin",
        full_name = "Ana Agrež",
        email = "ana.agrez@example.com",
        hashed_password = "$2b$12$kUnbsxhy3ns9e0d//MWxQuKYphkusjav6NBwqX/lK2QlY7Yzt8sHS"  # "njah"
    ),
    models.UserModel(
        uid = 1,
        username = "berta",
        access_level = "user",
        full_name = "Berta Bohak",
        email = "berta.bohak@example.com",
        hashed_password = "$2b$12$i14mgMTbkf.O22Qnkz6AfOAJ9xendDRTOHEc8ey90Z9QQfwSOuy6."  # "njeh"
    ),
    models.UserModel(
        uid = 2,
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


def get_all_users(db: Session) -> dict:
    return dict(db.query(models.UserModel.uid, models.UserModel.username).all())
