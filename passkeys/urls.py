from django.urls import path
from . import FIDO2, views

app_name = "passkeys"
urlpatterns = [
    path("", views.index, name="home"),
    path("registration/begin", FIDO2.reg_begin, name="reg_begin"),
    path("registration/complete", FIDO2.reg_complete, name="reg_complete"),
    path("auth/begin", FIDO2.auth_begin, name="auth_begin"),
    path("auth/complete", FIDO2.auth_complete, name="auth_complete"),
    path("login/", views.login_options, name="login"),
    path("login/passkey/", views.passkey_login, name="login.passkey"),
    path("login/otp/", views.otp_login, name="login.otp"),
    path("add/", views.add, name="add"),
    path("del/", views.del_key, name="delKey"),
    path("toggle/", views.toggle_key, name="toggle"),
]
