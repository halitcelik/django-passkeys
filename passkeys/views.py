import datetime
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render
from django.utils.timezone import now as utc_now

from .models import UserPasskey, OTP
from django.utils.translation import gettext_lazy as _
from .forms import PasswordLoginForm, OTPLoginForm, PasskeyLoginForm

from django.conf import settings
from django.contrib.auth import get_user_model, login, logout
from django.utils.translation import gettext_lazy as _
from passkeys.backend import PasskeyBackendException
from passkeys.FIDO2 import (
    auth_complete,
)
from passkeys.models import UserPasskey

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.exceptions import ValidationError
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.translation import gettext_lazy as _
from .forms import LoginOptionsForm, PasskeyLoginForm, PasswordLoginForm

UserModel = get_user_model()


def login_view(request):
    next_ = request.GET.get("next", request.POST.get("next", "/"))
    button_text = _("Next")
    template = "passkeys/auth/login.html"
    auth_data = {}
    login_options = []
    if hasattr(request, "htmx") and request.htmx:
        template = "auth/includes/login-form.html"
    if request.method == "POST":
        form = PasswordLoginForm(request.POST)
        if request.POST.get("password"):
            try:
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
                            f"""
                            Email adresse or password wrong. No account yet?
                            <a href='{reverse("auth.signup")}'>Signup</a>"""
                        )
                    ),
                )
        elif request.POST.get("passkeys"):
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
        elif request.POST.get("otp"):
            otp = OTP.objects.filter(
                key=request.POST.get("otp"),
                email=request.POST.get("email"),
                created_at__gte=utc_now() - datetime.timedelta(seconds=60),
            )
            if otp.exists():
                form = OTPLoginForm(request.POST)
                otp = otp.first()
                user = UserModel.objects.get(email=form.cleaned_data.get("email"))
                login(request, user)
                return HttpResponseRedirect(
                    request.GET.get("next", form.cleaned_data.get("next", "/"))
                )

        user_passkey = UserPasskey.objects.filter(
            user__email=request.POST.get("email"), enabled=True
        ).first()
        username = request.POST.get(UserModel.USERNAME_FIELD)
        filter_args = {UserModel.USERNAME_FIELD: username}
        user = UserModel.objects.filter(**filter_args)
        if user.exists():
            login_options.append("otp")
        if user_passkey is not None:
            login_options.append("passkey")
            request.session["base_username"] = username
            form = PasskeyLoginForm(
                initial={"next": next_, "email": request.POST.get("email")}
            )
        elif username:
            login_options.append("password")
            form = PasswordLoginForm(
                initial={"next": next_, "email": request.POST.get("email")}
            )
        button_text = _("Signin")

    else:
        form = LoginOptionsForm(initial={"next": next_})

    return render(
        request,
        template,
        {
            "form": form,
            "next": next_,
            "button_text": button_text,
            "current_page": "auth.login",
            "auth_data": auth_data,
            "login_options": login_options,
        },
    )


def logout_view(request):
    logout(request)
    return HttpResponseRedirect("/")


@login_required
def index(request, enroll=False):  # noqa
    keys = UserPasskey.objects.filter(user=request.user)  # pragma: no cover
    return render(
        request, "passkeys/passkeys.html", {"keys": keys, "enroll": enroll}
    )  # pragma: no cover


@login_required
def del_key(request):
    key = UserPasskey.objects.get(id=request.GET["id"])
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
