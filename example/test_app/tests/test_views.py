import json
from django.test import TransactionTestCase, Client, override_settings, tag
from django.urls import reverse
from passkeys.models import UserPasskey, OTP
from .test_fido import test_fido
from django.contrib.auth import get_user_model
from passkeys.forms import LoginOptionsForm, PasswordLoginForm

class TestViews(TransactionTestCase):

    def setUp(self) -> None:

        if not getattr(self, "assertEquals", None):
            self.assertEquals = self.assertEqual

        self.user_model = get_user_model()
        self.client = Client()
        self.user = self.user_model.objects.create_user(
            username="test1", password="test1", email="test1@test.com"
        )
        self.user2 = self.user_model.objects.create_user(
            username="test2", password="test2", email="test2@test.com"
        )
        self.passkey = UserPasskey.objects.create(user=self.user, credential_id="test_creds", name="test_key")

    def test_disabling_key(self):
        self.client.post(
            "/passkeys/login/",
            {"email": "test1@test.com", "password": "test1", "passkeys": ""},
        )
        res = self.client.post(reverse("passkeys:toggle"), json.dumps({"id": str(self.passkey.id)}), content_type='application/json')
        self.assertFalse(UserPasskey.objects.get(id=self.passkey.id).enabled)

        self.client.post(reverse("passkeys:toggle"), json.dumps({"id": str(self.passkey.id)}), content_type='application/json')
        self.assertTrue(UserPasskey.objects.get(id=self.passkey.id).enabled)

    def test_deleting_key(self):
        self.client.post(
            "/passkeys/login/",
            {"email": "test1@test.com", "password": "test1", "passkeys": ""},
        )
        key = UserPasskey.objects.filter(user=self.user).latest("id")
        self.client.post(reverse("passkeys:delKey"), json.dumps({"id": str(key.id)}), content_type='application/json')
        self.assertEquals(UserPasskey.objects.filter(id=key.id).count(), 0)
    
    def test_wrong_ownership(self):
        self.client.post(
            "/passkeys/login/",
            {"email": "test2@test.com", "password": "test2", "passkeys": ""},
        )
        key = UserPasskey.objects.filter(user=self.user).latest("id")
        
        r = self.client.post(reverse("passkeys:delKey"), json.dumps({"id": str(key.id)}), content_type='application/json')        
        self.assertEquals(r.status_code, 403)
        self.assertEquals(
            r.content, b"Error: You don't own this token so you can't delete it"
        )
        r = self.client.post(reverse("passkeys:toggle"), json.dumps({"id": str(key.id)}), content_type='application/json')
        self.assertEquals(r.status_code, 403)
        self.assertEquals(
            r.content, b"Error: You don't own this token so you can't toggle it"
        )

class LoginOptionsViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.login_options_url = reverse("passkeys:login")
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(
            username="test", email="testuser@example.com", password="testpassword"
        )

    def test_get_login_options(self):
        response = self.client.get(self.login_options_url)
        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passkeys/login.html")
        self.assertIsInstance(response.context["form"], LoginOptionsForm)

    
    def test_post_login_options_with_valid_password_email(self):
        response = self.client.post(
            self.login_options_url,
            {
                "email": self.user.email,
                "password": "testpassword",
                "next": "/passkeys/"
            },
        )

        self.assertRedirects(
            response, expected_url="/passkeys/", status_code=302, target_status_code=200
        )

    def test_post_login_options_with_invalid_password(self):
        response = self.client.post(
            self.login_options_url,
            {
                "email": self.user.email,
                "password": "wrongpassword",
            },
        )

        self.assertFormError(
            response, "form", None, "Email adresse or password wrong. No account yet?"
        )

    def test_post_login_options_with_invalid_email(self):
        response = self.client.post(
            self.login_options_url,
            {
                "email": "nonexistentuser@test.com",
                "password": "testpassword",
            },
        )

        self.assertFormError(
            response, "form", None, "Email adresse or password wrong. No account yet?"
        )
    def test_post_login_options_without_password(self):
        self.user = self.user_model.objects.create_user(
            username="test2", password="test2", email="test2@test.com"
        )
        response = self.client.post(
            self.login_options_url,
            {
                "email": "test2@test.com",
                "password": "",
            },
        )
        self.assertIsInstance(response.context['form'], PasswordLoginForm)


class OTPLoginViewTest(TransactionTestCase):

    def setUp(self):
        self.user_model = get_user_model()
        self.user = self.user_model.objects.create_user(email="testuser@example.com", username="test", password="test")
        self.client = Client()
        self.otp_login_url = reverse("passkeys:login.otp")

    def test_get_otp_login_raises_405(self):
        response = self.client.get(self.otp_login_url)
        self.assertEqual(response.status_code, 405)
    def test_post_otp_login_with_valid_otp(self):
        OTP.objects.create(key="123456", email=self.user.email)
        response = self.client.post(
            self.otp_login_url,
            {
                "otp": "123456",
                "email": self.user.email,
                "next": "/passkeys/"
            },
        )

        self.assertRedirects(
            response, expected_url="/passkeys/", status_code=302, target_status_code=200
        )
    def test_post_otp_login_with_invalid_otp(self):
        OTP.objects.create(key="123456", email=self.user.email)

        response = self.client.post(
            self.otp_login_url,
            {
                "otp": "654321",
                "email": self.user.email,
            },
        )

        self.assertFormError(
            response,
            "form",
            "otp",
            "Your OTP code is either expired or invalid. Ask a new one.",
        )
        
    def test_post_otp_login_without_otp(self):
        self.assertFalse(OTP.objects.filter(email=self.user.email).exists())
        self.client.post(
            self.otp_login_url,
            {
                "email": self.user.email,
            },
        )
        self.assertTrue(OTP.objects.filter(email=self.user.email).exists())
    def test_post_otp_login_resend_otp(self):

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

class IndexViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.index_url = reverse("passkeys:home")
    
    def test_index_view_with_authenticated_user(self):
        user = get_user_model().objects.create_user(
            username="testuser", password="testpassword", email="test@test.com"
        )
        self.client.login(email="test@test.com", password="testpassword")

        UserPasskey.objects.create(user=user, credential_id="key1", name="test")
        UserPasskey.objects.create(user=user, credential_id="key2", name="test")

        response = self.client.get(self.index_url)

        self.assertEqual(response.status_code, 200)
        self.assertTemplateUsed(response, "passkeys/passkeys.html")
        keys = UserPasskey.objects.filter(user=user).values_list("credential_id", flat=True)
        for key in response.context["keys"]:
            self.assertIn(key.credential_id, keys)

class DeleteKeyViewTest(TransactionTestCase):

    def setUp(self):
        self.client = Client()
        self.delete_key_url = reverse("passkeys:delKey")

    def test_delete_key(self):
        user = get_user_model().objects.create_user(
            username="testuser", password="testpassword"
        )
        self.client.login(username="testuser", password="testpassword")

        key = UserPasskey.objects.create(user=user, credential_id="testkey", name="test")

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

        self.assertEqual(response.status_code, 302)#redirects to login
        


@override_settings(
    AUTHENTICATION_BACKENDS=(
        "django.contrib.auth.backends.ModelBackend",
        "test_app.backends.EmailBackend",
        "passkeys.backend.PasskeyModelBackend",
    ),
    LOGIN_URL="/passkeys/login/",
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

        key = UserPasskey.objects.create(
            user=user, token="testkey", name="testkey", credential_id="testcredential"
        )

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
        print(response.content.decode())
        self.assertEqual(response.status_code, 302)
        self.assertRedirects(response, "/passkeys/login/?next=/passkeys/toggle/")


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
