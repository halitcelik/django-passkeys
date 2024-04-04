from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    uuid = models.UUIDField(default=uuid.uuid4)
    username = models.CharField(
        max_length=512, blank=True, null=True, unique=True, editable=False
    )
    email = models.EmailField(verbose_name="email address", max_length=512, unique=True)

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.get_full_name() or self.email
