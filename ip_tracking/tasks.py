from celery import shared_task
from celery.schedules import crontab
from django.utils import timezone
from django.db.models import Count, Q
from django.db import transaction
from .models import RequestLog, SuspiciousIP, AnomalyDetectionConfig, BlockedIP
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

@shared_task
def detect_suspicious_ips():
    """
    Celery task to detect suspicious IP addresses based on:
    1. High traffic (100+ requests per hour)
    2. Access to sensitive paths (/admin, /login, etc.)
    3. Multiple authentication failures
    """
    try:
        # Get configuration values with defaults
        high_traffic_threshold = int(AnomalyDetectionConfig.get_config('high_traffic_threshold', '100'))
        detection_period_minutes = int(AnomalyDetectionConfig.get_config('detection_period_minutes', '60'))
        
        # Define sensitive paths
        sensitive_paths = [
            '/admin/', '/admin/login/', '/api/login/', '/login/',
            '/api/admin/', '/wp-admin/', '/phpmyadmin/', '/server-status/',
            '/config/', '/env/', '/.env', '/.git/', '/backup/'
        ]
        
        # Calculate time threshold
        time_threshold = timezone.now() - timedelta(minutes=detection_period_minutes)
        
        logger.info(f"Starting suspicious IP detection for period: {time_threshold}")
        
        # Detect high traffic IPs
        detect_high_traffic_ips(time_threshold, high_traffic_threshold)
        
        # Detect sensitive path access
        detect_sensitive_path_access(time_threshold, sensitive_paths)
        
        # Detect multiple authentication failures
        detect_auth_failures(time_threshold)
        
        # Clean up old suspicious IP entries
        cleanup_old_suspicious_ips()
        
        logger.info("Suspicious IP detection completed successfully")
        
    except Exception as e:
        logger.error(f"Error in detect_suspicious_ips task: {str(e)}")
        raise

def detect_high_traffic_ips(time_threshold, threshold):
    """Detect IPs with excessive requests"""
    high_traffic_ips = RequestLog.objects.filter(
        timestamp__gte=time_threshold
    ).values('ip_address').annotate(
        request_count=Count('id')
    ).filter(
        request_count__gte=threshold
    ).exclude(
        ip_address__in=SuspiciousIP.objects.filter(is_active=True).values_list('ip_address', flat=True)
    )
    
    for ip_data in high_traffic_ips:
        ip_address = ip_data['ip_address']
        request_count = ip_data['request_count']
        
        with transaction.atomic():
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': SuspiciousIP.SuspicionReason.HIGH_TRAFFIC,
                    'description': f"High traffic detected: {request_count} requests in the last hour",
                    'request_count': request_count,
                    'is_active': True
                }
            )
            
            if not created:
                suspicious_ip.reason = SuspiciousIP.SuspicionReason.HIGH_TRAFFIC
                suspicious_ip.description = f"High traffic detected: {request_count} requests in the last hour"
                suspicious_ip.request_count = request_count
                suspicious_ip.last_detected = timezone.now()
                suspicious_ip.is_active = True
                suspicious_ip.save()
        
        logger.warning(f"High traffic detected from IP {ip_address}: {request_count} requests")

def detect_sensitive_path_access(time_threshold, sensitive_paths):
    """Detect IPs accessing sensitive paths"""
    sensitive_access_ips = RequestLog.objects.filter(
        timestamp__gte=time_threshold,
        path__in=sensitive_paths
    ).values('ip_address', 'path').annotate(
        access_count=Count('id')
    ).exclude(
        ip_address__in=SuspiciousIP.objects.filter(is_active=True).values_list('ip_address', flat=True)
    )
    
    for ip_data in sensitive_access_ips:
        ip_address = ip_data['ip_address']
        path = ip_data['path']
        access_count = ip_data['access_count']
        
        with transaction.atomic():
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': SuspiciousIP.SuspicionReason.SENSITIVE_ACCESS,
                    'description': f"Access to sensitive path: {path} ({access_count} times)",
                    'request_count': access_count,
                    'sensitive_paths': [path],
                    'is_active': True
                }
            )
            
            if not created:
                # Update existing entry
                current_paths = set(suspicious_ip.sensitive_paths or [])
                current_paths.add(path)
                suspicious_ip.reason = SuspiciousIP.SuspicionReason.SENSITIVE_ACCESS
                suspicious_ip.description = f"Access to sensitive paths: {', '.join(current_paths)}"
                suspicious_ip.request_count += access_count
                suspicious_ip.sensitive_paths = list(current_paths)
                suspicious_ip.last_detected = timezone.now()
                suspicious_ip.is_active = True
                suspicious_ip.save()
        
        logger.warning(f"Sensitive path access from IP {ip_address}: {path} ({access_count} times)")

def detect_auth_failures(time_threshold):
    """Detect IPs with multiple authentication failures"""
    auth_failure_ips = RequestLog.objects.filter(
        timestamp__gte=time_threshold,
        path__in=['/api/login/', '/login/', '/admin/login/'],
        # This would need additional logic to detect actual failures
        # For now, we'll assume high frequency to login paths indicates failures
    ).values('ip_address').annotate(
        attempt_count=Count('id')
    ).filter(
        attempt_count__gte=5  # 5+ login attempts in an hour
    ).exclude(
        ip_address__in=SuspiciousIP.objects.filter(is_active=True).values_list('ip_address', flat=True)
    )
    
    for ip_data in auth_failure_ips:
        ip_address = ip_data['ip_address']
        attempt_count = ip_data['attempt_count']
        
        with transaction.atomic():
            suspicious_ip, created = SuspiciousIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': SuspiciousIP.SuspicionReason.MULTIPLE_FAILURES,
                    'description': f"Multiple authentication attempts: {attempt_count} attempts in the last hour",
                    'request_count': attempt_count,
                    'is_active': True
                }
            )
            
            if not created:
                suspicious_ip.reason = SuspiciousIP.SuspicionReason.MULTIPLE_FAILURES
                suspicious_ip.description = f"Multiple authentication attempts: {attempt_count} attempts in the last hour"
                suspicious_ip.request_count = attempt_count
                suspicious_ip.last_detected = timezone.now()
                suspicious_ip.is_active = True
                suspicious_ip.save()
        
        logger.warning(f"Multiple auth attempts from IP {ip_address}: {attempt_count} attempts")

def cleanup_old_suspicious_ips():
    """Clean up suspicious IP entries older than 7 days"""
    cleanup_threshold = timezone.now() - timedelta(days=7)
    deleted_count, _ = SuspiciousIP.objects.filter(
        last_detected__lt=cleanup_threshold,
        is_active=False
    ).delete()
    
    logger.info(f"Cleaned up {deleted_count} old suspicious IP entries")

@shared_task
def auto_block_suspicious_ips():
    """
    Automatically block IPs that have been flagged as suspicious multiple times
    """
    try:
        auto_block_threshold = int(AnomalyDetectionConfig.get_config('auto_block_threshold', '3'))
        block_duration_days = int(AnomalyDetectionConfig.get_config('block_duration_days', '7'))
        
        # Find IPs with multiple suspicious activities
        frequent_suspicious_ips = SuspiciousIP.objects.filter(
            is_active=True
        ).values('ip_address').annotate(
            suspicion_count=Count('id')
        ).filter(
            suspicion_count__gte=auto_block_threshold
        )
        
        blocked_count = 0
        
        for ip_data in frequent_suspicious_ips:
            ip_address = ip_data['ip_address']
            
            # Check if already blocked
            if not BlockedIP.objects.filter(ip_address=ip_address).exists():
                BlockedIP.objects.create(
                    ip_address=ip_address,
                    reason=f"Automatically blocked due to {ip_data['suspicion_count']} suspicious activities"
                )
                blocked_count += 1
                logger.warning(f"Automatically blocked suspicious IP: {ip_address}")
        
        logger.info(f"Auto-blocked {blocked_count} suspicious IPs")
        
    except Exception as e:
        logger.error(f"Error in auto_block_suspicious_ips task: {str(e)}")
        raise
