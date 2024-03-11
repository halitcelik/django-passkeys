import uuid
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.translation import gettext_lazy as _


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
