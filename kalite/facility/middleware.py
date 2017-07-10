"""
"""
from django.conf import settings

from django.db.models import signals
from django.db.models.signals import post_save

from .models import Facility

FACILITY_CACHE_STALE = False

def refresh_session_facility_info(request, facility_count):
    # Fix for #1211
    # Free time to refresh the facility info, which is otherwise cached for efficiency
    request.session["facility_count"] = facility_count
    request.session["facility_exists"] = request.session["facility_count"] > 0


def flag_facility_cache(**kwargs):
    global FACILITY_CACHE_STALE
    FACILITY_CACHE_STALE = True

post_save.connect(flag_facility_cache, sender=Facility)

class AuthFlags:
    def process_request(self, request):
        request.is_admin = False
        request.is_teacher = False
        request.is_student = False
        request.is_logged_in = False
        request.is_django_user = False
        import json

        try:
            if request.session['is_admin']:
                request.is_admin = True

            if request.session['is_teacher']:
                request.is_teacher = True

            if request.session['is_logged_in']:
                request.is_logged_in = True
        except:
            pass

        from django.utils.html import escape
        if request.user.is_authenticated():
            # Django user
            with file("/home/charlo/mid_is_authenticated_user.txt",'w') as f:
                f.write(escape(request.user))
            with file("/home/charlo/mid_is_authenticated_REQ.txt",'w') as f:
                f.write(escape(request))
            request.is_logged_in = True
            request.is_django_user = True
            if request.user.is_superuser:
                request.is_admin = True
            if "facility_user" in request.session:
                pass#del request.session["facility_user"]

        elif "facility_user" in request.session:

            # Facility user
            with file("/home/charlo/mid_is_facility_user.txt",'w') as f:
                f.write(escape(request.session["facility_user"]))
            if request.session["facility_user"].is_teacher:
                request.is_admin = True
                request.is_teacher = True
            else:
                request.is_student = True
            request.is_logged_in = True


class FacilityCheck:
    def process_request(self, request):
        """
        Cache facility data in the session,
          while making sure anybody who can create facilities sees the real (non-cached) data
        """
        if not "facility_exists" in request.session or FACILITY_CACHE_STALE:
            # always refresh for admins, or when no facility exists yet.
            refresh_session_facility_info(request, facility_count=Facility.objects.count())
