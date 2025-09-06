from django.utils import timezone
from .models import RequestLog

class IPLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Code to be executed for each request before the view is called
        
        # Get the client IP address
        ip_address = self.get_client_ip(request)
        
        # Create and save the log entry
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path
        )
        
        response = self.get_response(request)
        
        # Code to be executed for each request/response after the view is called
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
