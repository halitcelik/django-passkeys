from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

User = get_user_model()


class EmailBackend(ModelBackend):
    def authenticate(self, request, email="", password="", **kwargs):

        users = User.objects.filter(email=email)
        for user in users:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

        return None
