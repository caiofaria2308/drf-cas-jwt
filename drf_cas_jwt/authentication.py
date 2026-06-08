import hmac
import hashlib

from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.exceptions import AuthenticationFailed
from rest_framework_simplejwt.authentication import JWTAuthentication

from .models import Token


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

        # Hash do token com HMAC-SHA256
        from django.conf import settings
        server_secret = settings.SECRET_KEY
        token_hash = hmac.new(
            server_secret.encode(),
            str(validated_token).encode(),
            hashlib.sha256
        ).hexdigest()

        # Validar que existe registro de token persistido
        token_record = Token.objects.filter(
            user=user,
            token=token_hash
        ).first()

        if not token_record:
            raise AuthenticationFailed(
                _("Token Not Valid"),
                code="bad_authorization_header",
            )

        return user, validated_token
