import hmac

from flask import  request
from werkzeug.security import check_password_hash, generate_password_hash

from app import modules
from app.config import Config
from . import gen_md5, random_choices
from .conn import conn_db

salt = 'arlsalt!@#'

# werkzeug 生成的哈希前缀，用于区分新老口令存储方案
STRONG_HASH_PREFIX = ("pbkdf2:", "scrypt:")


def verify_password(stored_password, password):
    """口令校验：兼容历史 MD5+固定盐方案与新注册用户的强哈希方案。"""
    if not stored_password or password is None:
        return False

    if str(stored_password).startswith(STRONG_HASH_PREFIX):
        try:
            return check_password_hash(stored_password, password)
        except Exception:
            return False

    # 历史方案：gen_md5(salt + password)
    return hmac.compare_digest(stored_password, gen_md5(salt + password))


def user_login(username = None, password = None):
    if not username or not password:
        return

    user = conn_db('user').find_one({"username": username})
    if not user or not verify_password(user.get("password"), password):
        return

    item = {
        "username": username,
        "token": gen_md5(random_choices(50)),
        "type": "login"
    }
    conn_db('user').update_one({"_id": user["_id"]}, {"$set": {"token": item["token"]}})

    # 历史 MD5 口令在登录成功后自动升级为强哈希
    if not str(user.get("password", "")).startswith(STRONG_HASH_PREFIX):
        conn_db('user').update_one({"_id": user["_id"]},
                                   {"$set": {"password": generate_password_hash(password)}})

    return item


def user_login_header():
    token = request.headers.get("Token") or request.args.get("token")

    if not Config.AUTH:
        return True

    item = {
        "username": "ARL-API",
        "token": Config.API_KEY,
        "type": "api"
    }


    if not token:
        return False

    if token == Config.API_KEY:
        return item


    data = conn_db('user').find_one({"token": token})
    if data:
        item["username"] = data.get("username")
        item["token"] = token
        item["type"] = "login"
        return item

    return False



def user_logout(token):
    if user_login_header():
        conn_db('user').update_one({"token": token}, {"$set": {"token": None}})


def change_pass(token, old_password, new_password):
    query = {"token": token, "password": gen_md5(salt + old_password)}
    data = conn_db('user').find_one(query)
    if data:
        conn_db('user').update_one({"token": token}, {"$set": {"password": gen_md5(salt + new_password)}})
        return True
    else:
        return False


import functools


def auth(func):
    ret = {
        "message": "not login",
        "code": 401,
        "data": {}
    }

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        if Config.AUTH and not user_login_header():
            return  ret

        return func(*args, **kwargs)

    return wrapper