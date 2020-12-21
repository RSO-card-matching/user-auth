# pylint: disable=no-name-in-module

from typing import Optional

from pydantic import BaseModel
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Boolean, Column, Integer, String


Base = declarative_base()


class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    uid: Optional[int] = None


class User(BaseModel):
    uid: int
    username: str
    access_level: str
    email: Optional[str] = None
    full_name: Optional[str] = None

    class Config:
        orm_mode = True

class UserSensitive(User):
    hashed_password: str

class UserNew(BaseModel):
    username: str
    password: str
    email: str
    full_name: Optional[str] = None

class UserUpdate(BaseModel):
    password: Optional[str] = None
    email: Optional[str] = None
    full_name: Optional[str] = None

class UserModel(Base):
    __tablename__ = "users"
    uid = Column(Integer, primary_key = True, index = True)
    username = Column(String, index = True)
    access_level = Column(String, index = True)
    email = Column(String)
    full_name = Column(String)
    hashed_password = Column(String)
