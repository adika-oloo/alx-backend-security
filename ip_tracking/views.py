from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.views import View
from ratelimit.decorators import ratelimit
from ratelimit.core import get_usage
from django.contrib.auth.decorators import login_required
from django.utils import timezone
from .models import RequestLog
import json

# Function-based view with rate limiting
@ratelimit(key='ip', rate='5/m', method=['POST'], block=True)
@ratelimit(key='user_or_ip', rate='10/m', method=['POST'], block=True)
@csrf_exempt
def login_view(request):
    """
    Login view with rate limiting applied
    - 5 requests per minute for anonymous users by IP
    - 10 requests per minute for authenticated users
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            username = data.get('username')
            password = data.get('password')
            
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                # Log successful login
                RequestLog.objects.create(
                    ip_address=get_client_ip(request),
                    path=request.path,
                    country='N/A',
                    city='N/A',
                    isp='N/A'
                )
                return JsonResponse({'status': 'success', 'message': 'Login successful'})
            else:
                return JsonResponse({'status': 'error', 'message': 'Invalid credentials'}, status=401)
                
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

@login_required
def logout_view(request):
    """
    Logout view (only accessible to authenticated users)
    """
    logout(request)
    return JsonResponse({'status': 'success', 'message': 'Logout successful'})

@ratelimit(key='ip', rate='10/m', block=True)
def api_status(request):
    """
    Public API status endpoint with rate limiting
    """
    return JsonResponse({
        'status': 'ok',
        'timestamp': timezone.now().isoformat(),
        'message': 'API is running'
    })

@ratelimit(key='user', rate='20/m', block=True)
@login_required
def user_profile(request):
    """
    User profile endpoint with rate limiting for authenticated users
    """
    user = request.user
    return JsonResponse({
        'username': user.username,
        'email': user.email,
        'last_login': user.last_login.isoformat() if user.last_login else None,
        'date_joined': user.date_joined.isoformat()
    })

# Class-based view with rate limiting
@method_decorator(ratelimit(key='ip', rate='5/m', block=True), name='dispatch')
@method_decorator(ratelimit(key='user_or_ip', rate='10/m', block=True), name='dispatch')
class SensitiveDataView(View):
    """
    Class-based view for sensitive data with rate limiting
    """
    
    def get(self, request):
        # Check rate limit status
        usage = get_usage(request, key='ip', rate='5/m', method=['GET'], increment=False)
        
        return JsonResponse({
            'sensitive_data': 'This is protected information',
            'rate_limit': {
                'remaining': usage.get('remaining', 0),
                'limit': usage.get('limit', 0),
                'reset_time': usage.get('reset_time', 0)
            }
        })
    
    def post(self, request):
        # Process sensitive data
        return JsonResponse({'status': 'success', 'message': 'Data processed'})

# Utility function to get client IP
def get_client_ip(request):
    """
    Get the client's IP address from the request object
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

# Rate limit status endpoint
@ratelimit(key='ip', rate='1/m', block=True)
def rate_limit_status(request):
    """
    Endpoint to check current rate limit status
    """
    ip_usage = get_usage(request, key='ip', rate='5/m', increment=False)
    user_usage = get_usage(request, key='user', rate='10/m', increment=False) if request.user.is_authenticated else None
    
    response_data = {
        'ip_address': get_client_ip(request),
        'ip_rate_limit': {
            'remaining': ip_usage.get('remaining', 0),
            'limit': ip_usage.get('limit', 0),
            'reset_time': ip_usage.get('reset_time', 0)
        }
    }
    
    if user_usage:
        response_data['user_rate_limit'] = {
            'remaining': user_usage.get('remaining', 0),
            'limit': user_usage.get('limit', 0),
            'reset_time': user_usage.get('reset_time', 0)
        }
    
    return JsonResponse(response_data)
