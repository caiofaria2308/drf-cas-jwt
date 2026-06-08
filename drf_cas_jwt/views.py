import hmac
import hashlib

from django.conf import settings
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django_cas_ng import views as cas_views
from rest_framework import status
from django.contrib.auth import logout as logout_django
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import update_last_login
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError

from .models import Token
from .settings import settings as drf_settings
from .rate_limit import check_rate_limit, reset_rate_limit, increment_rate_limit
from .refresh_utils import (
    is_token_valid,
    log_token_event,
    mark_as_rotated,
    revoke_token_family,
    detect_and_revoke_reuse,
    create_refresh_token_family,
)


def get_ipaddress(request):
    """Extract client IP from request, considering X-Forwarded-For."""
    user_ip = request.META.get("HTTP_X_FORWARDED_FOR")
    if user_ip:
        ip = user_ip.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def hash_token_hmac(token):
    """Hash token with HMAC-SHA256 using server secret."""
    server_secret = settings.SECRET_KEY
    return hmac.new(
        server_secret.encode(),
        str(token).encode(),
        hashlib.sha256
    ).hexdigest()


class CasLogin(cas_views.LoginView):
    """
    CAS login view: creates JWT tokens and stores token hash with refresh tracking.
    """

    def successful_login(self, request: HttpRequest, next_page: str) -> HttpResponse:
        """
        Successful login flow: create JWT tokens, hash + persist token,
        register refresh token family, set cookies.

        :param request: HTTP request
        :param next_page: Redirect URL after login
        :return: HTTP response with tokens in cookies + JSON body
        """
        if not request.GET.get("ticket"):
            logout_django(request)
            next_page = drf_settings.CAS_JWT_LOGIN_REDIRECT
            return HttpResponseRedirect(
                f"{drf_settings.CAS_JWT_LOGOUT_REDIRECT}?next={next_page}"
            )

        user = request.user

        # Create refresh and access tokens
        refresh = RefreshToken.for_user(request.user)
        access_token = refresh.access_token
        refresh_token = str(refresh)

        update_last_login(None, user)
        ip = get_ipaddress(request)

        # Hash access token with HMAC-SHA256
        token_hash = hash_token_hmac(access_token)

        # Persist access token record
        Token.objects.create(
            user=user,
            token=token_hash,
            ip=ip,
            jti=refresh.get('jti', None),
        )

        # Register refresh token family for rotation tracking
        refresh_jti = refresh.get('jti', None)
        if refresh_jti:
            create_refresh_token_family(
                jti=refresh_jti,
                user=user,
                ip=ip,
            )

        # Log login event
        log_token_event(
            user=user,
            event='LOGIN',
            reason='success',
            ip=ip,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
        )

        # For admin endpoints, redirect with tokens (legacy)
        if "/admin" in next_page:
            bracket = "" if settings.FRONTEND_AUTH_REDIRECT[-1] == "/" else "/"
            redirect_url = (
                f"{settings.FRONTEND_AUTH_REDIRECT}{bracket}"
                f"{access_token}/{refresh_token}/"
            )
            return HttpResponseRedirect(redirect_url)

        # For frontend: set secure cookies + JSON response
        response = Response({
            'access_token': str(access_token),
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
            }
        })

        # Set refresh token as HttpOnly secure cookie
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            max_age=settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME', 7 * 24 * 60 * 60).total_seconds(),
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict',
            path='/',
        )

        return response


class CasLogout(APIView):
    """
    Logout endpoint: revokes token and refresh token family.
    POST autenticado + idempotente.
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request, format=None):
        """
        Logout: extract token from Authorization header, revoke it.
        Always returns success (idempotent).

        :param request: HTTP request
        :param format: Response format
        :return: HTTP response
        """
        try:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header[7:]
                token_hash = hash_token_hmac(token)

                # Delete token record
                token_record = Token.objects.filter(token=token_hash).first()
                if token_record:
                    # Revoke refresh token family
                    if token_record.jti:
                        revoke_token_family(token_record.jti)

                    # Log logout
                    log_token_event(
                        user=token_record.user,
                        event='LOGOUT',
                        reason='success',
                        ip=get_ipaddress(request),
                    )

                    token_record.delete()
        except Exception:
            # Silently fail - logout is idempotent
            pass

        logout_django(request)

        response = HttpResponseRedirect(drf_settings.CAS_JWT_LOGOUT_REDIRECT)
        response.delete_cookie('refresh_token', path='/')
        return response


class CasTokenRefreshView(APIView):
    """
    Endpoint de renovação de tokens (v1.0.1).

    Lê o refresh_token do cookie HttpOnly, valida, detecta reuse, rotaciona
    e retorna novo access_token + atualiza cookie com novo refresh_token.

    POST /auth/token/refresh/
    (sem body — refresh_token enviado automaticamente pelo navegador via cookie)
    """

    authentication_classes = []
    permission_classes = []

    def post(self, request, format=None):
        """
        Rotaciona refresh token e emite novo access token.

        :param request: HTTP request com cookie refresh_token
        :param format: Response format
        :return: JSON com novo access_token ou 401/429 em caso de falha
        """
        ip = get_ipaddress(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')

        refresh_token_str = request.COOKIES.get('refresh_token')
        if not refresh_token_str:
            return Response(
                {'detail': 'Refresh token não encontrado.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        try:
            refresh = RefreshToken(refresh_token_str)
        except TokenError:
            return Response(
                {'detail': 'Refresh token inválido ou expirado.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        old_jti = refresh.get('jti', None)
        user_id = refresh.get('user_id', None)

        if not old_jti or not user_id:
            return Response(
                {'detail': 'Token malformado.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        from django.contrib.auth import get_user_model
        User = get_user_model()

        try:
            user = User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return Response(
                {'detail': 'Usuário não encontrado.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Rate limiting por usuário + IP
        is_limited, _ = check_rate_limit(
            user_id=user.id,
            ip=ip,
            action='refresh',
        )
        if is_limited:
            log_token_event(
                user=user,
                event='REFRESH_DENIED',
                reason='rate_limit',
                ip=ip,
                user_agent=user_agent,
            )
            return Response(
                {'detail': 'Muitas tentativas. Tente novamente mais tarde.'},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

        # Detectar reuse (replay de token já rotacionado)
        is_reuse, _ = detect_and_revoke_reuse(
            jti=old_jti,
            user=user,
            ip=ip,
            user_agent=user_agent,
        )
        if is_reuse:
            increment_rate_limit(user_id=user.id, ip=ip, action='refresh')
            return Response(
                {'detail': 'Token inválido. Faça login novamente.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Validar que o token ainda está ativo (não foi revogado)
        if not is_token_valid(old_jti):
            log_token_event(
                user=user,
                event='REFRESH_DENIED',
                reason='invalid_token',
                ip=ip,
                user_agent=user_agent,
            )
            increment_rate_limit(user_id=user.id, ip=ip, action='refresh')
            return Response(
                {'detail': 'Refresh token foi revogado.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )

        # Rotacionar: marcar old_jti como rotacionado e criar novo
        mark_as_rotated(old_jti)

        new_refresh = RefreshToken.for_user(user)
        new_access = new_refresh.access_token
        new_jti = new_refresh.get('jti', None)

        # Criar nova família com parent_jti rastreado
        create_refresh_token_family(
            jti=new_jti,
            user=user,
            ip=ip,
            parent_jti=old_jti,
        )

        # Atualizar Token record: substituir jti antigo pelo novo
        token_hash = hash_token_hmac(str(new_access))
        Token.objects.filter(user=user, jti=old_jti, deleted_at__isnull=True).update(
            jti=new_jti,
            token=token_hash,
        )

        # Log de sucesso e reset rate limit
        log_token_event(
            user=user,
            event='REFRESH',
            reason='success',
            ip=ip,
            user_agent=user_agent,
        )
        reset_rate_limit(user_id=user.id, ip=ip, action='refresh')

        response = Response({'access_token': str(new_access)})
        response.set_cookie(
            key='refresh_token',
            value=str(new_refresh),
            max_age=settings.SIMPLE_JWT.get('REFRESH_TOKEN_LIFETIME', 7 * 24 * 60 * 60).total_seconds(),
            httponly=True,
            secure=not settings.DEBUG,
            samesite='Strict',
            path='/',
        )
        return response
