import uuid
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.core.mail import EmailMultiAlternatives
from django.conf import settings


class UserPasskey(models.Model):
    uuid = models.UUIDField(_("UUID"), default=uuid.uuid4)
    user_model = get_user_model()
    user = models.ForeignKey(user_model, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    enabled = models.BooleanField(default=True)
    platform = models.CharField(max_length=255, default="")
    added_on = models.DateTimeField(auto_now_add=True)
    last_used = models.DateTimeField(null=True, default=None)
    credential_id = models.CharField(max_length=255, unique=True)
    token = models.CharField(max_length=255, null=False)

    def __str__(self):
        return f"UserPasskey: {self.user} - {self.name}"


class OTP(models.Model):
    email = models.EmailField(_("Email"), max_length=254)
    key = models.CharField(max_length=6, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def send(self):
        subject = _("Your one time pass code")
        if self.email and self.key:
            html = render_to_string(
                "passkeys/email/otp.html",
                {"code": self.code, "subject": subject},
            )
            text = strip_tags(
                render_to_string(
                    "passkeys/email/otp.html",
                    {
                        "code": self.code,
                        "subject": subject,
                    },
                )
            )
            email = EmailMultiAlternatives(
                subject=subject,
                body=text,
                from_email=settings.DEFAULT_FROM_EMAIL,
                to=self.email,
            )
            email.attach_alternative(html, "text/html")
            email.send()
