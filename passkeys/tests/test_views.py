import json
from django.test import TransactionTestCase, Client, override_settings
from django.urls import reverse
from passkeys.models import UserPasskey, OTP
from .test_fido import test_fido
from django.contrib.auth import get_user_model
from passkeys.forms import LoginOptionsForm


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class TestViews(TransactionTestCase):

    def setUp(self) -> None:

        if not getattr(self, "assertEquals", None):
            self.assertEquals = self.assertEqual

        self.user_model = get_user_model()
        # self.user = self.user_model.objects.create_user(username="test", password="test")
        self.client = Client()
        # self.client.post("/auth/login", {"username": "test", "password": "test", 'passkeys': ''})
        test = test_fido()
        test.setUp()
        self.authenticator = test.test_key_reg()
        self.user = self.user_model.objects.get(username="test")

        res = self.client.post(
            "/passkeys/login/", {"username": "test", "password": "test", "passkeys": ""}
        )

    def test_disabling_key(self):
        key = UserPasskey.objects.filter(user=self.user).latest("id")
        res = self.client.post(reverse("passkeys:toggle"), data={"id": str(key.id)})
        self.assertFalse(UserPasskey.objects.get(id=key.id).enabled)

        res2 = self.client.post(reverse("passkeys:toggle"), data={"id": str(key.id)})
        self.assertTrue(UserPasskey.objects.get(id=key.id).enabled)

    def test_deleting_key(self):
        key = UserPasskey.objects.filter(user=self.user).latest("id")
        res = self.client.post(reverse("passkeys:delKey"), data={"id": str(key.id)})
        self.assertEquals(UserPasskey.objects.filter(id=key.id).count(), 0)

    def test_wrong_ownership(self):
        test = test_fido()
        test.setUp()
        authenticator = test.test_key_reg()
        key = UserPasskey.objects.filter(user=self.user).latest("id")
        self.user = self.user_model.objects.create_user(
            username="test2", password="test2"
        )
        self.client.post(
            "/passkeys/login/",
            {"username": "test2", "password": "test2", "passkeys": ""},
        )
        r = self.client.post(reverse("passkeys:delKey"), data={"id": str(key.id)})
        self.assertEquals(r.status_code, 403)
        self.assertEquals(
            r.content, b"Error: You own this token so you can't delete it"
        )
        r = self.client.post(reverse("passkeys:toggle"), data={"id": str(key.id)})
        self.assertEquals(r.status_code, 403)
        self.assertEquals(
            r.content, b"Error: You own this token so you can't toggle it"
        )


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class LoginOptionsViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.login_options_url = reverse("passkeys:login")
        self.user_model = get_user_model()

    def test_get_login_options(self):
        response = self.client.get(self.login_options_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passkeys/login.html")
        self.assertIsInstance(response.context["form"], LoginOptionsForm)

    def test_post_login_options_with_valid_password_username(self):
        self.user_model.objects.create_user(
            username="testuser", password="testpassword"
        )

        response = self.client.post(
            self.login_options_url,
            {
                "username": "testuser",
                "password": "testpassword",
            },
        )
        print(response.content.decode())

        self.assertRedirects(
            response, expected_url="/", status_code=302, target_status_code=200
        )

    def test_post_login_options_with_valid_password_email(self):
        user = self.user_model.objects.create_user(
            email="testuser@example.com", password="testpassword"
        )

        response = self.client.post(
            self.login_options_url,
            {
                "email": "testuser@example.com",
                "password": "testpassword",
            },
        )

        self.assertRedirects(
            response, expected_url="/", status_code=302, target_status_code=200
        )

    def test_post_login_options_with_invalid_password(self):
        response = self.client.post(
            self.login_options_url,
            {
                "username": "testuser",
                "password": "wrongpassword",
            },
        )

        self.assertFormError(
            response, "form", None, "Email address or password wrong. No account yet?"
        )

    def test_post_login_options_with_invalid_username(self):
        response = self.client.post(
            self.login_options_url,
            {
                "username": "nonexistentuser",
                "password": "testpassword",
            },
        )

        self.assertFormError(
            response, "form", None, "Email address or password wrong. No account yet?"
        )

    def test_post_login_options_without_password(self):
        response = self.client.post(
            self.login_options_url,
            {
                "username": "testuser",
                "password": "",
            },
        )

        self.assertFormError(response, "form", None, "This field is required.")


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class OTPLoginViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.otp_login_url = reverse("otp_login")
        self.user_model = get_user_model()

    def test_get_otp_login(self):
        response = self.client.get(self.otp_login_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passkeys/otp-login.html")
        self.assertIn("form", response.context)
        self.assertIn("next", response.context)
        self.assertIn("otp_invalid", response.context)
        self.assertIn("button_text", response.context)
        self.assertIn("login_options", response.context)

    def test_post_otp_login_with_valid_otp(self):
        user = self.user_model.objects.create_user(email="testuser@example.com")
        otp = OTP.objects.create(key="123456", email="testuser@example.com")

        response = self.client.post(
            self.otp_login_url,
            {
                "otp": "123456",
                "email": "testuser@example.com",
            },
        )

        self.assertRedirects(
            response, expected_url="/", status_code=302, target_status_code=200
        )

    def test_post_otp_login_with_invalid_otp(self):
        user = self.user_model.objects.create_user(email="testuser@example.com")
        otp = OTP.objects.create(key="123456", email="testuser@example.com")

        response = self.client.post(
            self.otp_login_url,
            {
                "otp": "654321",
                "email": "testuser@example.com",
            },
        )

        self.assertFormError(
            response,
            "form",
            "otp",
            "Your OTP code is either expired or invalid. Ask a new one.",
        )

    def test_post_otp_login_without_otp(self):
        response = self.client.post(
            self.otp_login_url,
            {
                "email": "testuser@example.com",
            },
        )

        self.assertFormError(response, "form", "otp", "This field is required.")

    def test_post_otp_login_resend_otp(self):
        self.user_model.objects.create_user(email="testuser@example.com")

        response = self.client.post(
            self.otp_login_url,
            {
                "email": "testuser@example.com",
                "resend_otp": True,
            },
        )

        self.assertEqual(response.context["button_text"], "Verify")

        self.assertTrue(OTP.objects.filter(email="testuser@example.com").exists())

        self.assertEqual(response.status_code, 200)


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class IndexViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.index_url = reverse("index")

    def test_index_view_with_authenticated_user(self):
        user = get_user_model().objects.create_user(
            username="testuser", password="testpassword"
        )
        self.client.login(username="testuser", password="testpassword")

        UserPasskey.objects.create(user=user, key="key1")
        UserPasskey.objects.create(user=user, key="key2")

        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passkeys/passkeys.html")

        self.assertQuerysetEqual(
            response.context["keys"],
            UserPasskey.objects.filter(user=user),
            transform=lambda x: x,
        )

    def test_index_view_redirects_when_not_authenticated(self):
        response = self.client.get(self.index_url)
        self.assertRedirects(response, "/accounts/login/?next=/index")


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class DeleteKeyViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.delete_key_url = reverse("del_key")

    def test_delete_key(self):
        user = get_user_model().objects.create_user(
            username="testuser", password="testpassword"
        )
        self.client.login(username="testuser", password="testpassword")

        key = UserPasskey.objects.create(user=user, key="testkey")

        response = self.client.post(
            self.delete_key_url,
            json.dumps({"id": key.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "Deleted Successfully")

    def test_delete_key_without_authentication(self):
        response = self.client.post(
            self.delete_key_url, json.dumps({"id": 1}), content_type="application/json"
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.content.decode(),
            "Error: You don't own this token so you can't delete it",
        )


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class ToggleKeyViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.toggle_key_url = reverse("passkeys:toggle")

    def test_toggle_key(self):
        user = get_user_model().objects.create_user(
            username="testuser", password="testpassword"
        )
        self.client.login(username="testuser", password="testpassword")

        key = UserPasskey.objects.create(user=user, key="testkey")

        response = self.client.post(
            self.toggle_key_url,
            json.dumps({"id": key.id}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    def test_toggle_key_without_authentication(self):
        response = self.client.post(
            self.toggle_key_url, json.dumps({"id": 1}), content_type="application/json"
        )

        self.assertEqual(response.status_code, 403)
        self.assertEqual(
            response.content.decode(),
            "Error: You don't own this token so you can't toggle it",
        )


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    )
)
class AddViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.add_url = reverse("passkeys:add")

    def test_add_view(self):
        get_user_model().objects.create_user(
            username="testuser", password="testpassword"
        )
        self.client.login(username="testuser", password="testpassword")

        response = self.client.get(self.add_url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passkeys/add.html")

    def test_add_view_without_authentication(self):
        response = self.client.get(self.add_url)

        self.assertEqual(response.status_code, 302)  # Redirects to login page
