from django.utils import timezone
from django.http import HttpResponseForbidden
from .models import RequestLog, BlockedIP

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Get the client IP address
        ip_address = self.get_client_ip(request)
        
        # Check if IP is blocked
        if self.is_ip_blocked(ip_address):
            return HttpResponseForbidden(
                f"Access denied. Your IP address ({ip_address}) has been blocked."
            )
        
        # Create and save the log entry
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path
        )
        
        response = self.get_response(request)
        return response
    
    def get_client_ip(self, request):
        """
        Get the client's IP address from the request object.
        Handles various proxy scenarios.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # X-Forwarded-For header can contain multiple IPs, the first one is the original client
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    def is_ip_blocked(self, ip_address):
        """Check if the IP address is in the blocked list"""
        return BlockedIP.objects.filter(ip_address=ip_address).exists()
