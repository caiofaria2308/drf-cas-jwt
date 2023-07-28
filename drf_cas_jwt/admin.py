from django.contrib import admin

from .models import Device, Token


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "name"]
    ordering = ["name"]


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ["id", "device", "created_at"]
    list_display_links = ["id"]
    ordering = ["-created_at"]
