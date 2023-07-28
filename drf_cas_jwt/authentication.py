import hashlib

from django.utils.translation import gettext_lazy as _
from django_user_agents.utils import get_user_agent
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import AuthenticationFailed

from .models import Device, Token


class CasJwtAuthentication(JWTAuthentication):
    def authenticate(self, request):
        authenticate = super().authenticate(request)
        if not authenticate:
            raise AuthenticationFailed(
                _("Token Not Valid"),
                code="bad_authorization_header",
            )
        user = authenticate[0]
        validated_token = authenticate[1]

        device_data = get_user_agent(request)
        device = Device.objects.filter(
            name=device_data.device.family,
            user=user,
            os_family=device_data.os.family,
            browser_family=device_data.browser.family,
        )
        token = hashlib.md5(str(validated_token).encode()).hexdigest()
        token = Token.objects.filter(device__in=device, token=token)
        if token.exists():
            return user, validated_token
        raise AuthenticationFailed(
            _("Token Not Valid"),
            code="bad_authorization_header",
        )
