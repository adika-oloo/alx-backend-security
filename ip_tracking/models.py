from django.db import models
from django.core.exceptions import ValidationError
import ipaddress

class RequestLog(models.Model):
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    path = models.CharField(max_length=255)
    
    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Request Log'
        verbose_name_plural = 'Request Logs'
    
    def __str__(self):
        return f"{self.ip_address} - {self.timestamp} - {self.path}"


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
