from django.contrib import admin

from .models import Device, Token


@admin.register(Device)
class DeviceAdmin(admin.ModelAdmin):
    list_display = ["id", "user", "name"]
    ordering = ["name"]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(Token)
class TokenAdmin(admin.ModelAdmin):
    list_display = ["id", "device", "created_at"]
    list_display_links = ["id"]
    ordering = ["-created_at"]

    def has_add_permission(self, request) -> bool:
        return False

    def has_change_permission(self, request, obj=None) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False
