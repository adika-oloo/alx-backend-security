from django.contrib import admin
from .models import RequestLog, BlockedIP, GeolocationCache

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'country', 'city', 'path', 'timestamp')
    list_filter = ('country', 'city', 'timestamp')
    search_fields = ('ip_address', 'path', 'country', 'city')
    readonly_fields = ('ip_address', 'timestamp', 'path', 'country', 'city', 
                      'region', 'latitude', 'longitude', 'timezone', 'isp')
    fieldsets = (
        ('Basic Info', {
            'fields': ('ip_address', 'path', 'timestamp')
        }),
        ('Geolocation', {
            'fields': ('country', 'country_name', 'city', 'region', 
                      'latitude', 'longitude', 'timezone', 'isp')
        }),
    )

@admin.register(BlockedIP)
class BlockedIPAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'created_at', 'reason')
    list_filter = ('created_at',)
    search_fields = ('ip_address', 'reason')

@admin.register(GeolocationCache)
class GeolocationCacheAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'country', 'city', 'updated_at')
    list_filter = ('country', 'updated_at')
    search_fields = ('ip_address', 'country', 'city')
    readonly_fields = ('ip_address', 'created_at', 'updated_at')
