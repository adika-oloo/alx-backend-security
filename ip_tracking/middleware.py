from django.utils import timezone
from django.http import HttpResponseForbidden
from django.core.cache import cache
import requests
import json
from .models import RequestLog, BlockedIP, GeolocationCache

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
        
        # Get geolocation data (with caching)
        geolocation_data = self.get_geolocation_data(ip_address)
        
        # Create and save the log entry
        RequestLog.objects.create(
            ip_address=ip_address,
            path=request.path,
            **geolocation_data
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
    
    def get_geolocation_data(self, ip_address):
        """
        Get geolocation data for an IP address with caching
        Uses multiple fallback methods for geolocation
        """
        # Check if IP is private/local
        if self.is_private_ip(ip_address):
            return {
                'country': None,
                'country_name': None,
                'city': None,
                'region': None,
                'latitude': None,
                'longitude': None,
                'timezone': None,
                'isp': None
            }
        
        # Try to get from cache first
        cache_key = f'ip_geolocation_{ip_address}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return cached_data
        
        # Try database cache
        try:
            db_cache = GeolocationCache.objects.filter(ip_address=ip_address).first()
            if db_cache and not db_cache.is_expired():
                data = {
                    'country': db_cache.country,
                    'country_name': db_cache.country_name,
                    'city': db_cache.city,
                    'region': db_cache.region,
                    'latitude': db_cache.latitude,
                    'longitude': db_cache.longitude,
                    'timezone': db_cache.timezone,
                    'isp': db_cache.isp
                }
                # Store in Django cache for faster access
                cache.set(cache_key, data, timeout=86400)  # 24 hours
                return data
        except:
            # Database might not be ready yet
            pass
        
        # Get fresh geolocation data
        geolocation_data = self.fetch_geolocation_data(ip_address)
        
        # Update cache
        cache.set(cache_key, geolocation_data, timeout=86400)  # 24 hours
        
        # Update database cache
        try:
            GeolocationCache.objects.update_or_create(
                ip_address=ip_address,
                defaults=geolocation_data
            )
        except:
            pass
        
        return geolocation_data
    
    def is_private_ip(self, ip_address):
        """Check if IP address is private/reserved"""
        if ip_address.startswith('10.') or \
           ip_address.startswith('172.16.') or \
           ip_address.startswith('192.168.') or \
           ip_address == '127.0.0.1' or \
           ip_address == '::1':
            return True
        return False
    
    def fetch_geolocation_data(self, ip_address):
        """
        Fetch geolocation data from external API
        Uses multiple fallback providers
        """
        # Try ip-api.com first (free tier available)
        try:
            response = requests.get(f'http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query', timeout=2)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'country': data.get('countryCode'),
                        'country_name': data.get('country'),
                        'city': data.get('city'),
                        'region': data.get('regionName'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp')
                    }
        except:
            pass
        
        # Fallback to country.is API :cite[9]
        try:
            response = requests.get(f'https://api.country.is/{ip_address}', timeout=2)
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country'),
                    'country_name': None,
                    'city': None,
                    'region': None,
                    'latitude': None,
                    'longitude': None,
                    'timezone': None,
                    'isp': None
                }
        except:
            pass
        
        # Final fallback: return empty data
        return {
            'country': None,
            'country_name': None,
            'city': None,
            'region': None,
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'isp': None
        }


# Alternative implementation using django-ip-geolocation middleware
# Add this to your settings.py MIDDLEWARE instead if you prefer this approach
