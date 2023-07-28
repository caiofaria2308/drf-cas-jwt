from uuid import uuid4

from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone
from django_cas_ng.models import SessionTicket

from .managers import SoftDeleteManager, SoftDeleteManagerAdmin

User = get_user_model()


class Device(models.Model):
    MOBILE = "mobile"
    TABLET = "tablet"
    TOUCH_CAPABLE = "touch_capable"
    PC = "pc"
    BOT = "bot"
    TYPE_CHOICES = (
        (MOBILE, "Mobile"),
        (TABLET, "Tablet"),
        (TOUCH_CAPABLE, "Touch Capable"),
        (PC, "PC"),
        (BOT, "BOT"),
    )

    id = models.UUIDField(primary_key=True, default=uuid4)
    name = models.CharField(max_length=64)
    type = models.CharField(choices=TYPE_CHOICES, max_length=16)
    browser_family = models.CharField(max_length=64)
    browser_version = models.CharField(max_length=64)
    os_family = models.CharField(max_length=64)
    os_version = models.CharField(max_length=64)
    user = models.ForeignKey(User, on_delete=models.CASCADE)


class Token(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid4)
    ip = models.GenericIPAddressField()
    token = models.CharField(max_length=32, verbose_name="Token JWT (Criptografado)")
    device = models.ForeignKey(Device, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    deleted_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = SoftDeleteManager()
    admin_objects = SoftDeleteManagerAdmin()

    class Meta:
        unique_together = ("token", "device")

    def delete(self, hard_delete=False, *args, **kwargs):
        if hard_delete:
            return super().delete(*args, **kwargs)

        self.deleted_at = timezone.now()
        self.save()
