"""

New settings pattern

"""
import os
from django.conf import settings

BASE_DEMO_DIR = os.path.dirname(os.path.dirname(__file__))
SAML_FOLDER = os.path.join(BASE_DEMO_DIR, 'demo', 'saml')
