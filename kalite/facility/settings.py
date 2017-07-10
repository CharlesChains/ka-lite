#######################
# Set module settings
#######################

# Default facility name
INSTALL_FACILITY_NAME = None  # default to None, so can be translated to latest language at runtime.

# None means, use full hashing locally--turn off the password cache
PASSWORD_ITERATIONS_TEACHER = None
PASSWORD_ITERATIONS_STUDENT = None
assert PASSWORD_ITERATIONS_TEACHER is None or PASSWORD_ITERATIONS_TEACHER >= 1, "If set, PASSWORD_ITERATIONS_TEACHER must be >= 1"
assert PASSWORD_ITERATIONS_STUDENT is None or PASSWORD_ITERATIONS_STUDENT >= 1, "If set, PASSWORD_ITERATIONS_STUDENT must be >= 1"

# This should not be set, except in cases where additional security is desired.
PASSWORD_ITERATIONS_TEACHER_SYNCED = 5000
PASSWORD_ITERATIONS_STUDENT_SYNCED = 2500
assert PASSWORD_ITERATIONS_TEACHER_SYNCED >= 5000, "PASSWORD_ITERATIONS_TEACHER_SYNCED must be >= 5000"
assert PASSWORD_ITERATIONS_STUDENT_SYNCED >= 2500, "PASSWORD_ITERATIONS_STUDENT_SYNCED must be >= 2500"

PASSWORD_CONSTRAINTS = {
    'min_length': 6,
}


DISABLE_SELF_ADMIN = False  #

RESTRICTED_TEACHER_PERMISSIONS = False  # setting this to True will disable creating/editing/deleting facilties/students for teachers

# Setting this to True will eliminate the need for password authentication for student accounts
# Further, it will provide an autocomplete for any student account on typing.
SIMPLIFIED_LOGIN = False
import os
BASE_DIR = os.path.dirname(os.path.dirname(__file__))
SAML_FOLDER = os.path.join(BASE_DIR, 'saml')

LOGIN_URL = '/sp/sso/login/'
SAML2IDP_SIGNING = True
SAML2IDP_PRIVATE_KEY_FILE = os.path.join(SAML_FOLDER, 'private-key.pem')
SAML2IDP_CERTIFICATE_FILE = os.path.join(SAML_FOLDER, 'certificate.pem')
