from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

class Command(BaseCommand):
    help = 'Clears all users from the database'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force deletion without confirmation',
        )

    def handle(self, *args, **options):
        User = get_user_model()
        user_count = User.objects.count()
        
        if user_count == 0:
            self.stdout.write(self.style.SUCCESS('No users found in the database.'))
            return
        
        if not options['force']:
            confirm = input(f'Are you sure you want to delete all {user_count} users? This cannot be undone. [y/N]: ')
            if confirm.lower() != 'y':
                self.stdout.write(self.style.WARNING('Operation cancelled.'))
                return
        
        User.objects.all().delete()
        self.stdout.write(self.style.SUCCESS(f'Successfully deleted {user_count} users.')) 