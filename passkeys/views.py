import json
import datetime
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.timezone import now as utc_now

from .models import UserPasskey, OTP
from django.utils.translation import gettext_lazy as _
from string import digits
import random
from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.utils.translation import gettext_lazy as _
from passkeys.backend import PasskeyBackendException
from passkeys.FIDO2 import (
    auth_complete,
)
from django import forms
from passkeys.models import UserPasskey

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from .forms import LoginOptionsForm, PasswordLoginForm, OTPLoginForm

UserModel = get_user_model()


def login_options(request):
    next_ = request.GET.get("next", request.POST.get("next", "/"))
    button_text = _("Next")
    template = "passkeys/login.html"
    form = LoginOptionsForm(initial={"next": next_})
    filter_args = {UserModel.USERNAME_FIELD: None}
    options = []
    if hasattr(request, "htmx") and request.htmx:
        template = "passkeys/includes/login-form.html"
    if request.method == "POST":
        form = PasswordLoginForm(
            initial={
                UserModel.USERNAME_FIELD: request.POST.get(UserModel.USERNAME_FIELD),
                "next": next_,
            }
        )
        username = request.POST.get(UserModel.USERNAME_FIELD)
        filter_args = {UserModel.USERNAME_FIELD: username}
        user = UserModel.objects.filter(**filter_args)
        if user.exists():
            if request.POST.get("password"):
                try:
                    form = PasswordLoginForm(request.POST)
                    if form.is_valid():
                        form.login_user(request)
                        return HttpResponseRedirect(
                            request.GET.get("next", form.cleaned_data.get("next", "/"))
                        )
                except PasskeyBackendException:
                    form.add_error(
                        field=None,
                        error=ValidationError(
                            mark_safe(
                                f"Email adresse or password wrong. No account yet?"
                            )
                        ),
                    )

            passkeys = UserPasskey.objects.filter(user=user.first())
            if passkeys.exists():
                options.append({"value": "passkey", "text": "Login with passkey"})
            options.append({"value": "otp", "text": _("Receive email code")})
        elif request.POST.get("password"):
            # User does not exist but they tried to login with password.
            # We need to try to validate the form to be able to add error to it.
            # Validating falls into PasskeyBackendException, we catch it.
            try:
                form = PasswordLoginForm(request.POST)
                form.is_valid()

            except PasskeyBackendException:
                form.add_error(
                    field=None,
                    error=ValidationError(
                        mark_safe("Email adresse or password wrong. No account yet?")
                    ),
                )

    return render(
        request,
        template,
        {
            **filter_args,
            "form": form,
            "next": next_,
            "button_text": button_text,
            "current_page": "auth.login",
            "login_options": options,
        },
    )


def passkey_login(request):
    next_ = request.GET.get("next", request.POST.get("next", "/"))
    if request.method == "POST":
        if request.POST.get("passkeys"):
            user = auth_complete(request)
            if user:
                login(
                    request,
                    user,
                    backend=[
                        be
                        for be in settings.AUTHENTICATION_BACKENDS
                        if "PasskeyModelBackend" in be
                    ][0],
                )
                return HttpResponseRedirect(next_)
        else:
            return render(request, "passkeys/login.html")


def otp_login(request):
    next_ = request.GET.get("next", request.POST.get("next", "/"))
    button_text = _("Verify")
    otp_invalid = False
    if request.method == "POST":
        form = LoginOptionsForm(request.POST)
        email = request.POST.get("email")
        if OTP.objects.filter(
            email=email, created_at__gte=utc_now() - datetime.timedelta(seconds=60)
        ).exists():
            form = OTPLoginForm(request.POST)
            if request.POST.get("otp"):
                form = OTPLoginForm(request.POST)
                if form.is_valid():
                    otp = OTP.objects.filter(
                        key=form.cleaned_data.get("otp"),
                        email=form.cleaned_data.get("email"),
                        created_at__gte=utc_now() - datetime.timedelta(seconds=60),
                    )
                    if otp.exists():
                        otp = otp.first()
                        user = UserModel.objects.get(email=request.POST.get("email"))
                        login(
                            request,
                            user,
                            backend=[
                                be
                                for be in settings.AUTHENTICATION_BACKENDS
                                if "EmailBackend" in be
                            ][0],
                        )
                        return HttpResponseRedirect(
                            request.GET.get("next", form.cleaned_data.get("next", "/"))
                        )
                    else:
                        otp_invalid = True
                        form.add_error(
                            "otp",
                            _(
                                "Your OTP code is either expired or invalid. Ask a new one."
                            ),
                        )
                        form.fields.pop("otp")
                        form.fields["email"].widget = forms.EmailInput()
                        button_text = _("Resend verification code")
        else:
            form = OTPLoginForm(request.POST)
            new_otp = OTP.objects.create(
                key="".join(random.choice(digits) for i in range(6)),
                email=request.POST.get("email"),
            )
            new_otp.send()
            button_text = _("Verify")
        return render(
            request,
            "passkeys/otp-login.html",
            {
                "form": form,
                "next": next_,
                "otp_invalid": otp_invalid,
                "button_text": button_text,
            },
        )


@login_required
def index(request):  # noqa
    keys = UserPasskey.objects.filter(user=request.user)  # pragma: no cover
    return render(
        request, "passkeys/passkeys.html", {"keys": keys}
    )  # pragma: no cover


@login_required
def del_key(request):
    data = json.loads(request.body)
    key = UserPasskey.objects.filter(id=data.get("id"))
    if key.exists():
        key = key.first()
    else:
        return HttpResponse(
            "Error: You don't own this token so you can't delete it", status=403
        )

    if key.user.pk == request.user.pk:
        key.delete()
        return HttpResponse("Deleted Successfully")
    return HttpResponse(
        "Error: You don't own this token so you can't delete it", status=403
    )


@login_required
def toggle_key(request):
    id = request.GET["id"]
    q = UserPasskey.objects.filter(user=request.user, id=id)
    if q.count() == 1:
        key = q[0]
        key.enabled = not key.enabled
        key.save()
        return HttpResponse("OK")
    return HttpResponse(
        "Error: You don't own this token so you can't toggle it", status=403
    )


@login_required
def add(request):
    return render(request, "passkeys/add.html")
