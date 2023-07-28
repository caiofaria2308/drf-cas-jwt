import hashlib

from django.conf import settings
from django.contrib.auth import logout as logout_django
from django.contrib.auth.models import update_last_login
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.utils.translation import gettext_lazy as _
from django_cas_ng import views as cas_views
from django_user_agents.utils import get_user_agent
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken

from .models import Device, Token
from .settings import settings as drf_settings


def get_ipaddress(request):
    user_ip = request.META.get("HTTP_X_FORWARDED_FOR")
    if user_ip:
        ip = user_ip.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


class CasLogin(cas_views.LoginView):
    def successful_login(self, request: HttpRequest, next_page: str) -> HttpResponse:
        """
        This method is called on successful login. Override this method for
        custom post-auth actions (i.e, to add a cookie with a token).


        :param request:
        :param next_page:
        :return:
        """
        if not request.GET.get("ticket"):
            logout_django(request)
            next_page = drf_settings.CAS_JWT_LOGIN_REDIRECT
            return HttpResponseRedirect(
                f"{drf_settings.CAS_JWT_LOGOUT_REDIRECT}?next={next_page}"
            )

        user = request.user

        refresh = RefreshToken.for_user(request.user)

        # create jwt token
        jwt_token = refresh.access_token
        refresh_token = str(refresh)
        update_last_login(None, user)
        device_data = get_user_agent(request)
        device = Device.objects.filter(
            name=device_data.device.family,
            user=user,
            os_family=device_data.os.family,
            browser_family=device_data.browser.family,
        )
        if not device.exists():
            device_type = None
            if device_data.is_mobile:
                device_type = Device.MOBILE
            elif device_data.is_tablet:
                device_type = Device.TABLET
            elif device_data.is_touch_capable:
                device_type = Device.TOUCH_CAPABLE
            elif device_data.is_pc:
                device_type = Device.PC
            elif device_data.is_bot:
                device_type = Device.BOT
            device = Device.objects.create(
                name=device_data.device.family,
                type=device_type,
                browser_family=device_data.browser.family,
                browser_version=device_data.browser.version_string,
                os_family=device_data.os.family,
                os_version=device_data.os.version_string,
                user=user,
            )
        else:
            device = device.first()
        Token.objects.filter(device=device).delete()
        token = hashlib.md5(str(jwt_token).encode()).hexdigest()
        Token.objects.create(token=token, device=device, ip=get_ipaddress(request))
        if "/admin" in next_page:
            return HttpResponseRedirect(next_page)

        bracket = "" if settings.FRONTEND_AUTH_REDIRECT[-1] == "/" else "/"

        new_next_page = next_page
        new_next_page = (
            f"{settings.FRONTEND_AUTH_REDIRECT}{bracket}{jwt_token}/{refresh_token}/"
        )
        return HttpResponseRedirect(new_next_page)


class CasLogout(APIView):
    def get(self, request, format=None):
        logout_django(request)
        token = request.headers["Authorization"].split(" ")[1]
        token = hashlib.md5(str(token).encode()).hexdigest()
        Token.objects.filter(token=token).delete()
        return HttpResponseRedirect(drf_settings.CAS_JWT_LOGOUT_REDIRECT)
