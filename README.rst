
DRF Cas JWT
=========================================


DRF-cas-jwt is a app to use DRF with a CAS server, using JWT to authenticate.


Quick start
-----------

1. Add "drf_cas_jwt" and "django_user_agents" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...,
        "django_user_agents",
        "drf_cas_jwt",
    ]

2. Add "UserAgentMiddleware" to your MIDDLEWARE setting like this::

    MIDDLEWARE = [
        ...,
        "django_user_agents.middleware.UserAgentMiddleware",
    ]

3. Set the variable CAS_JWT_LOGOUT_REDIRECT and CAS_JWT_LOGIN_REDIRECT in settings.py

4. Add "CasJwtAuthentication" to your REST_FRAMEWORK setting like this (Remember to disable JWTAuthentication)::

    REST_FRAMEWORK = {
        "DEFAULT_AUTHENTICATION_CLASSES": [
            ...,
            "drf_cas_jwt.authentication.CasJwtAuthentication",
            # "rest_framework_simplejwt.authentication.JWTAuthentication",
        ]
    }

5. Include the drf_cas_jwt URLconf in your project urls.py like this::

    from drf_cas_jwt.views import CasLogin, CasLogout
    path("login", CasLogin.as_view(), name="cas-jwt-login"),
    path("logout", CasLogout.as_view(), name="cas-jwt-logout"),

6. Run ``python manage.py migrate`` to create the drf_cas_jwt models.
