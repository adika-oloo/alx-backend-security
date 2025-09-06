from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError
from ip_tracking.models import BlockedIP
import ipaddress

class Command(BaseCommand):
    help = 'Block one or more IP addresses by adding them to the BlockedIP model'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='One or more IP addresses to block'
        )
        parser.add_argument(
            '--reason',
            type=str,
            help='Reason for blocking the IP address(es)'
        )
    
    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        reason = options.get('reason')
        
        success_count = 0
        error_count = 0
        
        for ip in ip_addresses:
            try:
                # Validate IP address format
                ipaddress.ip_address(ip)
                
                # Create blocked IP entry
                blocked_ip, created = BlockedIP.objects.get_or_create(
                    ip_address=ip,
                    defaults={'reason': reason}
                )
                
                if created:
                    self.stdout.write(
                        self.style.SUCCESS(f'Successfully blocked IP: {ip}')
                    )
                    success_count += 1
                else:
                    self.stdout.write(
                        self.style.WARNING(f'IP already blocked: {ip}')
                    )
                    
            except ValueError:
                self.stdout.write(
                    self.style.ERROR(f'Invalid IP address format: {ip}')
                )
                error_count += 1
            except IntegrityError:
                self.stdout.write(
                    self.style.WARNING(f'IP already blocked: {ip}')
                )
            except Exception as e:
                self.stdout.write(
                    self.style.ERROR(f'Error blocking IP {ip}: {str(e)}')
                )
                error_count += 1
        
        # Summary
        self.stdout.write(
            self.style.SUCCESS(
                f'\nOperation completed. Success: {success_count}, Errors: {error_count}'
            )
        )
