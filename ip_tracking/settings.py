# django-ip-geolocation settings :cite[1]:cite[6]
IP_GEOLOCATION_SETTINGS = {
    'BACKEND': 'django_ip_geolocation.backends.IPGeolocationAPI',
    'BACKEND_API_KEY': '',  # Add your API key if using a paid service
    'BACKEND_EXTRA_PARAMS': {},
    'RESPONSE_HEADER': 'X-IP-Geolocation',
    'ENABLE_REQUEST_HOOK': True,
    'ENABLE_RESPONSE_HOOK': True,
    'ENABLE_COOKIE': False,
    'FORCE_IP_ADDR': None,
    'USER_CONSENT_VALIDATOR': None
}

# Cache settings (using Redis recommended for production)
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        'LOCATION': 'unique-snowflake',
    }
}

# Alternatively, for production use Redis:
# CACHES = {
#     "default": {
#         "BACKEND": "django_redis.cache.RedisCache",
#         "LOCATION": "redis://127.0.0.1:6379/1",
#         "OPTIONS": {
#             "CLIENT_CLASS": "django_redis.client.DefaultClient",
#         }
#     }
# }

# Add to MIDDLEWARE
MIDDLEWARE = [
    # ... other middleware
    'ip_tracking.middleware.IPLoggingMiddleware',
    # Optionally add django_ip_geolocation middleware if using that package
    # 'django_ip_geolocation.middleware.IpGeolocationMiddleware',
]
