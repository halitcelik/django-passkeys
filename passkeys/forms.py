from typing import Any, Mapping
from django import forms
from django.contrib.auth import authenticate, get_user_model, login
from django.forms.renderers import BaseRenderer
from django.forms.utils import ErrorList
from django.utils.translation import gettext_lazy as _


UserModel = get_user_model()


class LoginOptionsForm(forms.Form):
    email = forms.EmailField(
        label=_("Your email adress"),
        required=True,
        widget=forms.EmailInput(
            attrs={"autofocus": True, "autocomplete": "username webauthn"}
        ),
    )
    username = forms.CharField(label=_("Your username"), max_length=155, required=True)
    next = forms.CharField(required=False, widget=forms.HiddenInput())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if UserModel.USERNAME_FIELD == "email":
            self.fields.pop("username")
        else:
            self.fields.pop("email")


class PasskeyLoginForm(LoginOptionsForm):
    passkeys = forms.HiddenInput(attrs={"id": "passkeys", "name": "passkeys"})


class PasswordLoginForm(LoginOptionsForm):
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(),
    )

    def clean(self):
        email_or_username, password = (
            self.cleaned_data.get(UserModel.USERNAME_FIELD),
            self.cleaned_data.get("password"),
        )
        kwargs = {UserModel.USERNAME_FIELD: email_or_username}
        user = authenticate(request=None, password=password, **kwargs)
        if user is None:
            self.add_error("password", _("Wrong email or password."))

    def login_user(self, request):
        assert self.is_bound
        email_or_username, password = (
            self.cleaned_data.get(UserModel.USERNAME_FIELD),
            self.cleaned_data.get("password"),
        )
        kwargs = {UserModel.USERNAME_FIELD: email_or_username}
        user = authenticate(request=request, password=password, **kwargs)
        if user.is_active:
            login(request, user)
            return user


class OTPLoginForm(forms.Form):
    otp = forms.CharField(required=False, label=_("OTP"), max_length=6)
    email = forms.EmailField(required=False, widget=forms.HiddenInput())
    next = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        fields = ("otp", "email", "next")
