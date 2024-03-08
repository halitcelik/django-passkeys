from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import render

from .models import UserPasskey
from django.utils.translation import gettext_lazy as _
from .forms import PasswordLoginForm, OTPLoginForm, PasskeyLoginForm

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.utils.translation import gettext_lazy as _
from passkeys.backend import PasskeyBackendException
from passkeys.FIDO2 import (
    auth_complete,
    enable_json_mapping,
    getServer,
    getUserCredentials,
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
    button_text = _("Continue")
    template = "passkeys/auth/login.html"
    auth_data = {}
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
                            Adresse email ou mot de passe erronée.
                            Pas de compte?
                            <a href='{reverse("auth.signup")}'>S'inscrire</a>"""
                        )
                    ),
                )

        else:
            if use_passkeys:
                passkey = request.POST.get("passkeys")
                if passkey:
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

                enable_json_mapping()
                User = get_user_model()
                credentials = getUserCredentials(request.POST.get(User.USERNAME_FIELD))
                server = getServer(request)
                user_passkey = UserPasskey.objects.filter(
                    user__email=request.POST.get("email"), enabled=True
                ).first()

                if user_passkey is not None:
                    auth_data, state = server.authenticate_begin(credentials)
                    auth_data = dict(auth_data)
                    request.session["fido2_state"] = state
                    form = PasskeyLoginForm(
                        initial={"next": next_, "email": request.POST.get("email")}
                    )
                else:
                    form = PasswordLoginForm(
                        initial={"next": next_, "email": request.POST.get("email")}
                    )
            button_text = _("Connexion")

    else:
        form = LoginOptionsForm(initial={"next": next_})

    return render(
        request,
        template,
        {
            "form": form,
            "next": next_,
            "page_title_override": _("Connexion"),
            "button_text": button_text,
            "current_page": "auth.login",
            "use_passkeys": use_passkeys,
            "auth_data": auth_data,
        },
    )


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
    return HttpResponse("Error: You own this token so you can't delete it", status=403)


@login_required
def toggle_key(request):
    id = request.GET["id"]
    q = UserPasskey.objects.filter(user=request.user, id=id)
    if q.count() == 1:
        key = q[0]
        key.enabled = not key.enabled
        key.save()
        return HttpResponse("OK")
    return HttpResponse("Error: You own this token so you can't toggle it", status=403)
