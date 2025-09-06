from django.db import models

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    country = models.CharField(max_length=2, blank=True, null=True, help_text="2-letter country code")
    country_name = models.CharField(max_length=100, blank=True, null=True, help_text="Full country name")
    city = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True, help_text="State/region")
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    timezone = models.CharField(max_length=50, blank=True, null=True)
    isp = models.CharField(max_length=100, blank=True, null=True, help_text="Internet Service Provider")
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['country']),
            models.Index(fields=['city']),
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.country} - {self.timestamp}"


class BlockedIP(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True, null=True, help_text="Optional reason for blocking this IP")
    
    class Meta:
        verbose_name = 'Blocked IP'
        verbose_name_plural = 'Blocked IPs'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.ip_address} (blocked at {self.created_at})"
    
    def clean(self):
        """Validate the IP address"""
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError:
            raise ValidationError(f"Invalid IP address: {self.ip_address}")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


# Cache model for geolocation data
class GeolocationCache(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)
    country = models.CharField(max_length=2, blank=True, null=True)
    country_name = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.FloatField(blank=True, null=True)
    longitude = models.FloatField(blank=True, null=True)
    timezone = models.CharField(max_length=50, blank=True, null=True)
    isp = models.CharField(max_length=100, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Geolocation Cache'
        verbose_name_plural = 'Geolocation Caches'
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.country} - {self.city}"
    
    def is_expired(self):
        """Check if cache entry is older than 24 hours"""
        return timezone.now() > self.updated_at + timezone.timedelta(hours=24)
