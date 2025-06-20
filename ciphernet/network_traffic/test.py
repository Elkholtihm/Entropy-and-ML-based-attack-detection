import os
import sys
import django
from pathlib import Path


DJANGO_PROJECT_PATH = Path(__file__).parent.parent
sys.path.append(str(DJANGO_PROJECT_PATH))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ciphernet.settings')
print(os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ciphernet.settings'))
django.setup()
