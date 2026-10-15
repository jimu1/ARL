"""
用户通过邮箱注册的核心逻辑。

安全设计要点（对应威胁建模报告 T1~T10）：
- T1 注册流程逐步校验：验证码校验通过后签发与邮箱强绑定的一次性 ticket，落库时二次校验票据与邮箱的绑定关系；
- T2 口令使用 werkzeug 的 pbkdf2-sha256（每用户独立随机盐），不再使用全局固定盐的 MD5；
- T3 验证码 6 位、错误 3 次立即失效、有效期 5 分钟、校验成功即失效、不在响应包中回显；
- T4 发码/注册接口按邮箱与来源 IP 限流，防止邮件轰炸与批量注册；
- T5 对外响应统一，不区分“邮箱是否已注册”，避免账号枚举；
- T6 邮件模板为静态文案，不拼接任何用户输入，避免模板注入；
- T7 日志中的邮箱一律脱敏，不记录验证码明文；
- T9 记录注册成功、验证码失败、限流拦截等安全日志。
"""

import hmac
import re
import secrets
import hashlib
import datetime

from werkzeug.security import generate_password_hash

from app.config import Config
from .conn import conn_db
from . import get_logger

logger = get_logger()

# 邮箱格式校验：仅允许常规字符，避免脏数据与注入
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)+$")

# 对外统一文案（防账号枚举：已注册与未注册返回一致）
GENERIC_SEND_MSG = "若该邮箱可用，验证码已发送，请注意查收（{} 分钟内有效）"
GENERIC_VERIFY_FAIL_MSG = "邮箱或验证码错误"
GENERIC_REGISTER_FAIL_MSG = "注册失败，请重新获取验证码后再试"
GENERIC_RATE_LIMIT_MSG = "操作过于频繁，请 {} 秒后再试"

# 验证码校验通过后签发的票据在传参时的字段名
TICKET_FIELD = "ticket"

_index_ready = False


def _now():
    """统一使用 UTC，保证 MongoDB TTL 索引的过期时间正确。"""
    return datetime.datetime.utcnow()


def _ensure_indexes():
    """惰性创建索引，避免在模块导入阶段就建立数据库连接。"""
    global _index_ready
    if _index_ready:
        return

    try:
        # TTL 索引：过期文档由 MongoDB 后台清理，业务侧仍会做显式过期判断
        conn_db("email_verify_code").create_index("expire_at", expireAfterSeconds=0)
        conn_db("email_verify_code").create_index("email")
        conn_db("email_verify_ticket").create_index("expire_at", expireAfterSeconds=0)
        conn_db("email_verify_ticket").create_index("ticket_hash")
        conn_db("register_rate").create_index("expire_at", expireAfterSeconds=0)
        # sparse：存量用户没有 email 字段，避免唯一索引把缺失值当作重复
        conn_db("user").create_index("email", unique=True, sparse=True)
        conn_db("user").create_index("username", unique=True, sparse=True)
        _index_ready = True
    except Exception as e:
        logger.warning("邮箱注册：创建索引失败 {}".format(e))


def mask_email(email):
    """邮箱脱敏：保留首位与 @ 后的域名，例如 w*******@qq.com"""
    if not email or "@" not in email:
        return "***"

    name, _, domain = email.partition("@")
    return "{}*******@{}".format(name[0], domain)


def is_valid_email(email):
    return bool(email) and bool(EMAIL_RE.match(email))


def _hash_code(code):
    """验证码哈希后落库，避免数据库泄露时验证码可被直接读取。"""
    return hashlib.sha256(str(code).encode()).hexdigest()


def _gen_code():
    """使用 secrets 生成密码学安全的 6 位验证码。"""
    return "".join(secrets.choice("0123456789") for _ in range(Config.REGISTER_CODE_LENGTH))


def check_password_policy(password):
    """校验口令强度，返回错误信息；通过时返回 None。"""
    if not password:
        return "密码不能为空"

    if len(password) < Config.REGISTER_PASSWORD_MIN_LENGTH:
        return "密码长度不能少于 {} 位".format(Config.REGISTER_PASSWORD_MIN_LENGTH)

    kinds = 0
    if re.search(r"[a-z]", password):
        kinds += 1
    if re.search(r"[A-Z]", password):
        kinds += 1
    if re.search(r"\d", password):
        kinds += 1
    if re.search(r"[^A-Za-z0-9]", password):
        kinds += 1

    if kinds < 3:
        return "密码需包含小写字母、大写字母、数字、特殊字符中的至少 3 种"

    for i in range(len(password) - 3):
        window = password[i:i + 4]
        if len(set(window)) == 1:
            return "密码不能包含连续 4 位重复字符"
        if all(ord(window[j + 1]) - ord(window[j]) == 1 for j in range(3)):
            return "密码不能包含连续 4 位顺序字符"
        if all(ord(window[j + 1]) - ord(window[j]) == -1 for j in range(3)):
            return "密码不能包含连续 4 位逆序字符"

    return None


def _rate_limit(scope, identity, limit, window_seconds):
    """滑动窗口限流，返回 (是否放行, 需等待秒数)。"""
    key = "{}:{}".format(scope, identity or "unknown")
    now = _now()
    window_start = now - datetime.timedelta(seconds=window_seconds)

    coll = conn_db("register_rate")
    doc = coll.find_one({"key": key}) or {}
    hits = [h for h in doc.get("hits", []) if isinstance(h, datetime.datetime) and h > window_start]

    if len(hits) >= limit:
        wait = int((hits[0] + datetime.timedelta(seconds=window_seconds) - now).total_seconds())
        return False, max(wait, 1)

    hits.append(now)
    coll.update_one(
        {"key": key},
        {"$set": {
            "key": key,
            "hits": hits,
            "expire_at": now + datetime.timedelta(seconds=window_seconds),
        }},
        upsert=True,
    )
    return True, 0


def _send_code_email(to_email, code):
    """使用静态模板发送验证码邮件（模板中不包含任何用户可控内容）。"""
    # 延迟导入：push 模块在 app.utils 包初始化时被引入，此处避免循环依赖
    from .push import send_email

    if not (Config.EMAIL_HOST and Config.EMAIL_USERNAME and Config.EMAIL_PASSWORD):
        raise RuntimeError("邮件服务未配置")

    title = "【ARL】邮箱注册验证码"
    html = (
        "<div style='font-family:sans-serif;font-size:14px;color:#333'>"
        "<p>尊敬的用户：</p>"
        "<p>您正在注册 ARL 账号，本次验证码为：</p>"
        "<p style='font-size:22px;font-weight:bold;letter-spacing:4px'>{code}</p>"
        "<p>验证码 {minutes} 分钟内有效，请勿泄露给他人。</p>"
        "<p>如非本人操作，请忽略本邮件。</p>"
        "</div>"
    ).format(code=code, minutes=Config.REGISTER_CODE_TTL // 60)

    send_email(host=Config.EMAIL_HOST, port=Config.EMAIL_PORT, mail=Config.EMAIL_USERNAME,
               password=Config.EMAIL_PASSWORD, to=to_email, title=title, html=html)


def _ok(message="success", data=None):
    return {"message": message, "code": 200, "data": data or {}}


def _fail(code, message):
    return {"message": message, "code": code, "data": {}}


def register_send_code(email, ip=None):
    """步骤 1：校验邮箱并向其发送注册验证码。"""
    if not Config.REGISTER_ENABLE:
        return _fail(403, "邮箱注册功能未开启")

    email = (email or "").strip().lower()
    if not is_valid_email(email):
        return _fail(301, "邮箱格式不正确")

    _ensure_indexes()

    # 限流：同一邮箱 60 秒内仅允许发送 1 次、每日上限；同一 IP 每小时上限
    allowed, wait = _rate_limit("send_interval", email, 1, Config.REGISTER_SEND_INTERVAL)
    if not allowed:
        return _fail(429, GENERIC_RATE_LIMIT_MSG.format(wait))

    allowed, wait = _rate_limit("send_email_daily", email, Config.REGISTER_SEND_DAILY_LIMIT, 86400)
    if not allowed:
        logger.warning("邮箱注册：邮箱 {} 触发每日发码上限".format(mask_email(email)))
        return _fail(429, GENERIC_RATE_LIMIT_MSG.format(wait))

    allowed, wait = _rate_limit("send_ip_hourly", ip, Config.REGISTER_SEND_IP_HOURLY_LIMIT, 3600)
    if not allowed:
        logger.warning("邮箱注册：IP {} 触发发码频率上限".format(ip))
        return _fail(429, GENERIC_RATE_LIMIT_MSG.format(wait))

    # 邮箱已注册时不发送邮件，但对外返回统一文案，避免账号枚举
    if conn_db("user").find_one({"email": email}):
        logger.info("邮箱注册：邮箱 {} 已注册，跳过发码".format(mask_email(email)))
        return _ok(GENERIC_SEND_MSG.format(Config.REGISTER_CODE_TTL // 60))

    code = _gen_code()
    now = _now()
    conn_db("email_verify_code").update_one(
        {"email": email},
        {"$set": {
            "email": email,
            "code_hash": _hash_code(code),
            "attempts": 0,
            "send_at": now,
            "expire_at": now + datetime.timedelta(seconds=Config.REGISTER_CODE_TTL),
            "ip": ip,
        }},
        upsert=True,
    )

    try:
        _send_code_email(email, code)
    except Exception as e:
        # 发送失败时清理验证码，避免留下无法送达的有效凭证
        conn_db("email_verify_code").delete_one({"email": email})
        logger.warning("邮箱注册：向 {} 发送验证码失败 {}".format(mask_email(email), e))
        return _fail(500, "验证码发送失败，请稍后重试")

    logger.info("邮箱注册：已向 {} 发送注册验证码".format(mask_email(email)))
    return _ok(GENERIC_SEND_MSG.format(Config.REGISTER_CODE_TTL // 60))


def register_verify_code(email, code, ip=None):
    """步骤 2：校验验证码。通过后签发与邮箱强绑定的一次性 ticket。"""
    if not Config.REGISTER_ENABLE:
        return _fail(403, "邮箱注册功能未开启")

    email = (email or "").strip().lower()
    code = (code or "").strip()

    if not is_valid_email(email) or not code:
        return _fail(301, GENERIC_VERIFY_FAIL_MSG)

    _ensure_indexes()
    now = _now()
    coll = conn_db("email_verify_code")
    doc = coll.find_one({"email": email})

    if not doc or not doc.get("expire_at") or doc["expire_at"] <= now:
        return _fail(302, GENERIC_VERIFY_FAIL_MSG)

    # 验证码错误 3 次后立即失效，需重新获取
    if doc.get("attempts", 0) >= Config.REGISTER_CODE_MAX_ATTEMPTS:
        coll.delete_one({"email": email})
        logger.warning("邮箱注册：{} 验证码尝试次数超限已失效".format(mask_email(email)))
        return _fail(303, GENERIC_VERIFY_FAIL_MSG)

    if not hmac.compare_digest(doc.get("code_hash", ""), _hash_code(code)):
        # 累计失败次数，达到上限时立即失效，用户需重新获取验证码
        if doc.get("attempts", 0) + 1 >= Config.REGISTER_CODE_MAX_ATTEMPTS:
            coll.delete_one({"email": email})
            logger.warning("邮箱注册：{} 验证码错误达到 {} 次已失效".format(
                mask_email(email), Config.REGISTER_CODE_MAX_ATTEMPTS))
        else:
            coll.update_one({"email": email}, {"$inc": {"attempts": 1}})
            logger.warning("邮箱注册：{} 验证码校验失败（IP {}）".format(mask_email(email), ip))
        return _fail(304, GENERIC_VERIFY_FAIL_MSG)

    # 校验成功：验证码一次性使用，立即失效
    coll.delete_one({"email": email})

    ticket = secrets.token_urlsafe(32)
    conn_db("email_verify_ticket").insert_one({
        "email": email,
        "ticket_hash": hashlib.sha256(ticket.encode()).hexdigest(),
        "used": False,
        "create_at": now,
        "expire_at": now + datetime.timedelta(seconds=Config.REGISTER_TICKET_TTL),
    })

    logger.info("邮箱注册：{} 验证码校验通过".format(mask_email(email)))
    return _ok("验证通过，请设置密码", {TICKET_FIELD: ticket})


def register_user(email, ticket, password, check_password, ip=None):
    """步骤 3：设置密码并创建账号。落库前二次校验 ticket 与邮箱的绑定关系。"""
    if not Config.REGISTER_ENABLE:
        return _fail(403, "邮箱注册功能未开启")

    email = (email or "").strip().lower()
    ticket = (ticket or "").strip()

    if not is_valid_email(email) or not ticket:
        return _fail(301, GENERIC_REGISTER_FAIL_MSG)

    if password != check_password:
        return _fail(302, "两次输入的密码不一致")

    error = check_password_policy(password)
    if error:
        return _fail(303, error)

    _ensure_indexes()

    allowed, wait = _rate_limit("register_ip_hourly", ip, Config.REGISTER_IP_HOURLY_LIMIT, 3600)
    if not allowed:
        logger.warning("邮箱注册：IP {} 触发注册频率上限".format(ip))
        return _fail(429, GENERIC_RATE_LIMIT_MSG.format(wait))

    now = _now()
    # 原子消费 ticket：一次性使用，且必须与本次提交的邮箱一致（防止用 A 邮箱的验证结果注册 B 邮箱）
    ticket_doc = conn_db("email_verify_ticket").find_one_and_update(
        {
            "ticket_hash": hashlib.sha256(ticket.encode()).hexdigest(),
            "used": False,
            "expire_at": {"$gt": now},
        },
        {"$set": {"used": True, "used_at": now}},
    )

    if not ticket_doc or ticket_doc.get("email") != email:
        logger.warning("邮箱注册：{} 的注册票据无效或与邮箱不匹配".format(mask_email(email)))
        return _fail(304, GENERIC_REGISTER_FAIL_MSG)

    if conn_db("user").find_one({"email": email}):
        logger.info("邮箱注册：邮箱 {} 已注册".format(mask_email(email)))
        return _fail(305, GENERIC_REGISTER_FAIL_MSG)

    try:
        conn_db("user").insert_one({
            "username": email,
            "email": email,
            # T2：pbkdf2-sha256 + 每用户独立随机盐，替代原有的 gen_md5(salt + password)
            "password": generate_password_hash(password),
            # 服务端固定为普通用户，不信任任何前端传入的角色字段
            "type": "user",
            "register_time": now,
            "register_ip": ip,
            "token": None,
        })
    except Exception as e:
        # 唯一索引冲突（并发注册）同样返回统一文案，避免账号枚举
        logger.warning("邮箱注册：创建用户 {} 失败 {}".format(mask_email(email), e))
        return _fail(306, GENERIC_REGISTER_FAIL_MSG)

    logger.info("邮箱注册：用户 {} 注册成功（IP {}）".format(mask_email(email), ip))
    return _ok("注册成功")
