from flask import request
from flask_restx import fields, Namespace
from app.utils import get_logger
from app.config import Config
from app import utils
from . import  ARLResource
from app import modules

ns = Namespace('user', description="管理员登录认证")

logger = get_logger()



login_fields = ns.model('LoginARL', {
    'username': fields.String(required=True, description="用户名"),
    'password': fields.String(required=True, description="密码"),
})


@ns.route('/login')
class LoginARL(ARLResource):

    @ns.expect(login_fields)
    def post(self):
        """
        用户登录
        """
        args = self.parse_args(login_fields)


        return build_data(utils.user_login(**args))




@ns.route('/logout')
class LogoutARL(ARLResource):

    def get(self):
        """
        用户退出
        """
        token = request.headers.get("Token")
        utils.user_logout(token)

        return build_data({})


change_pass_fields = ns.model('ChangePassARL', {
    'old_password': fields.String(required=True, description="旧密码"),
    'new_password': fields.String(required=True, description="新密码"),
    'check_password': fields.String(required=True, description="确认密码"),
})


@ns.route('/change_pass')
class ChangePassARL(ARLResource):
    @ns.expect(change_pass_fields)
    def post(self):
        """
        密码修改
        """
        args = self.parse_args(change_pass_fields)
        ret = {
            "message": "success",
            "code": 200,
            "data": {}
        }
        token = request.headers.get("Token")

        if args["new_password"] != args["check_password"]:
            ret["code"] = 301
            ret["message"] = "新密码和确定密码不一致"
            return ret

        if not args["new_password"]:
            ret["code"] = 302
            ret["message"] = "新密码不能为空"
            return ret

        if utils.change_pass(token, args["old_password"], args["new_password"]):
            utils.user_logout(token)
        else:
            ret["message"] = "旧密码错误"
            ret["code"] = 303

        return ret


register_email_fields = ns.model('RegisterEmailARL', {
    'email': fields.String(required=True, description="注册邮箱"),
})

register_verify_fields = ns.model('RegisterVerifyARL', {
    'email': fields.String(required=True, description="注册邮箱"),
    'code': fields.String(required=True, description="邮箱验证码"),
})

register_fields = ns.model('RegisterARL', {
    'email': fields.String(required=True, description="注册邮箱"),
    'ticket': fields.String(required=True, description="验证通过后返回的票据"),
    'password': fields.String(required=True, description="密码"),
    'check_password': fields.String(required=True, description="确认密码"),
})


def get_client_ip():
    """获取来源 IP。仅当服务部署在可信反向代理之后时，才信任 X-Forwarded-For。"""
    if Config.REGISTER_TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.remote_addr or "unknown"


@ns.route('/register/send_code')
class RegisterSendCodeARL(ARLResource):

    @ns.expect(register_email_fields)
    def post(self):
        """
        发送邮箱注册验证码
        """
        args = self.parse_args(register_email_fields)

        return utils.register_send_code(args["email"], get_client_ip())


@ns.route('/register/verify_code')
class RegisterVerifyCodeARL(ARLResource):

    @ns.expect(register_verify_fields)
    def post(self):
        """
        校验邮箱验证码，返回注册票据
        """
        args = self.parse_args(register_verify_fields)

        return utils.register_verify_code(args["email"], args["code"], get_client_ip())


@ns.route('/register')
class RegisterARL(ARLResource):

    @ns.expect(register_fields)
    def post(self):
        """
        用户注册（需先通过邮箱验证码校验）
        """
        args = self.parse_args(register_fields)

        return utils.register_user(args["email"], args["ticket"], args["password"],
                                   args["check_password"], get_client_ip())


def build_data(data):
    ret = {
        "message": "success",
        "code": 200,
        "data": {}
    }

    if data:
        ret["data"] = data
    else:
        ret["code"] = 401

    return ret


