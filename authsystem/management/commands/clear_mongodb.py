from django.core.management.base import BaseCommand
from pymongo import MongoClient
from django.conf import settings

class Command(BaseCommand):
    help = 'Clears all collections in MongoDB'

    def add_arguments(self, parser):
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force deletion without confirmation',
        )

    def handle(self, *args, **options):
        # Get MongoDB connection details from Django settings
        db_settings = settings.DATABASES['default']
        db_name = db_settings['NAME']
        
        # Get the connection string from the CLIENT settings
        client_settings = db_settings['CLIENT']
        connection_string = client_settings['host']
        
        # Connect to MongoDB using the connection string
        client = MongoClient(connection_string)
        db = client[db_name]
        
        # Get all collections
        collections = db.list_collection_names()
        
        if not collections:
            self.stdout.write(self.style.SUCCESS('No collections found in the database.'))
            return
        
        if not options['force']:
            confirm = input(f'Are you sure you want to delete all collections in {db_name}? This cannot be undone. [y/N]: ')
            if confirm.lower() != 'y':
                self.stdout.write(self.style.WARNING('Operation cancelled.'))
                return
        
        # Drop all collections
        for collection in collections:
            db[collection].drop()
            self.stdout.write(self.style.SUCCESS(f'Dropped collection: {collection}'))
        
        self.stdout.write(self.style.SUCCESS(f'Successfully cleared all collections in {db_name}.')) 