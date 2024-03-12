from django.urls import path
from . import FIDO2, views

app_name = "passkeys"
urlpatterns = [
    path("auth/begin", FIDO2.auth_begin, name="auth_begin"),
    path("auth/complete", FIDO2.auth_complete, name="auth_complete"),
    path("reg/begin", FIDO2.reg_begin, name="reg_begin"),
    path("reg/complete", FIDO2.reg_complete, name="reg_complete"),
    path("", views.index, name="home"),
    path("login/", views.login_options, name="login"),
    path("login/passkey/", views.passkey_login, name="login.passkey"),
    path("login/otp/", views.otp_login, name="login.otp"),
    path("login/", views.login_options, name="login"),
    path("enroll/", views.index, name="enroll", kwargs={"enroll": True}),
    path("del/", views.del_key, name="delKey"),
    path("toggle/", views.toggle_key, name="toggle"),
]
