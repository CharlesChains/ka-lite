#######################
# Set module settings
#######################

# Used for user logs.  By default, completely off.
#   NOTE: None means no limit (infinite)
USER_LOG_MAX_RECORDS_PER_USER = 1
USER_LOG_SUMMARY_FREQUENCY = (1, "day")

import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAML_FOLDER = os.path.join(BASE_DIR, 'saml')
LOGIN_URL = '/sp/sso/login/'
