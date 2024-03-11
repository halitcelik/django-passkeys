import os

from django import forms
from django.contrib.auth import authenticate, get_user_model, login
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
    next = forms.CharField(required=False, widget=forms.HiddenInput())


class PasskeyLoginForm(LoginOptionsForm):
    passkeys = forms.HiddenInput(attrs={"id": "passkeys", "name": "passkeys"})


class PasswordLoginForm(LoginOptionsForm):
    password = forms.CharField(
        label=_("Password"),
        widget=forms.PasswordInput(),
    )

    def clean(self):
        email, password = (
            self.cleaned_data.get("email"),
            self.cleaned_data.get("password"),
        )
        user = authenticate(request=None, email=email, password=password)
        if user is None:
            self.add_error("password", _("Wrong email or password."))

    def login_user(self, request):
        assert self.is_bound
        email, password = (
            self.cleaned_data.get("email"),
            self.cleaned_data.get("password"),
        )
        user = authenticate(request=request, email=email, password=password)
        if user.is_active:
            login(request, user)
            return user


class OTPLoginForm(forms.Form):
    otp = forms.CharField(label=_("OTP"), max_length=6, required=True)
    email = forms.HiddenInput()
    next = forms.CharField(required=False, widget=forms.HiddenInput())

    class Meta:
        fields = ("key", "email")
