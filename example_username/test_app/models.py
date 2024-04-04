from django.db import models
import uuid
from django.contrib.auth.models import AbstractUser


class User(AbstractUser):
    uuid = models.UUIDField(default=uuid.uuid4)
    username = models.CharField(
        max_length=512, unique=True
    )
    email = models.EmailField(verbose_name="email address", blank=True, null=True, max_length=512)

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.get_full_name() or self.email or self.username
