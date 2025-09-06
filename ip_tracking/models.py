from django.db import models
from django.core.exceptions import ValidationError
import ipaddress
from django.utils import timezone

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


class SuspiciousIP(models.Model):
    class SuspicionReason(models.TextChoices):
        HIGH_TRAFFIC = 'high_traffic', 'High Traffic (100+ requests/hour)'
        SENSITIVE_ACCESS = 'sensitive_access', 'Access to Sensitive Paths'
        MULTIPLE_FAILURES = 'multiple_failures', 'Multiple Authentication Failures'
        UNUSUAL_PATTERN = 'unusual_pattern', 'Unusual Access Pattern'
        SCANNING = 'scanning', 'Port Scanning or Probing'
    
    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=50, choices=SuspicionReason.choices)
    description = models.TextField(blank=True, null=True, help_text="Detailed description of suspicious activity")
    first_detected = models.DateTimeField(auto_now_add=True)
    last_detected = models.DateTimeField(auto_now=True)
    request_count = models.IntegerField(default=0, help_text="Number of requests in detection period")
    sensitive_paths = models.JSONField(default=list, blank=True, help_text="List of sensitive paths accessed")
    is_active = models.BooleanField(default=True, help_text="Whether this suspicion is currently active")
    
    class Meta:
        verbose_name = 'Suspicious IP'
        verbose_name_plural = 'Suspicious IPs'
        ordering = ['-last_detected']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['reason']),
            models.Index(fields=['is_active']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.get_reason_display()} - {self.last_detected}"
    
    def clean(self):
        """Validate the IP address"""
        try:
            ipaddress.ip_address(self.ip_address)
        except ValueError:
            raise ValidationError(f"Invalid IP address: {self.ip_address}")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)


class AnomalyDetectionConfig(models.Model):
    """Configuration model for anomaly detection parameters"""
    name = models.CharField(max_length=100, unique=True)
    value = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Anomaly Detection Configuration'
        verbose_name_plural = 'Anomaly Detection Configurations'
    
    def __str__(self):
        return f"{self.name}: {self.value}"
    
    @classmethod
    def get_config(cls, name, default=None):
        try:
            return cls.objects.get(name=name).value
        except cls.DoesNotExist:
            return default


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
