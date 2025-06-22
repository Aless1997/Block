import os
import django
from django.core.management import call_command

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Cripto.settings')
django.setup()

print("Eseguo le migrazioni...")
call_command('migrate', interactive=False)
print("Migrazioni completate.")
