from django.contrib import admin

from .models import Asset


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ("name", "asset_type", "status", "organization", "owner")
    list_filter = ("organization", "asset_type", "status")
    search_fields = ("name", "hostname")
