import os

from django import forms
from django.contrib.auth import authenticate, get_user_model, login
from django.utils.translation import gettext_lazy as _

from django.contrib.auth.forms import UserCreationForm

UserModel = get_user_model()


class EmailSignupForm(UserCreationForm):
    class Meta:
        model = UserModel
        fields = ("email",)


class UsernameSignupForm(UserCreationForm):
    class Meta:
        model = UserModel
        fields = ("username",)


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
