"""
Views for the KA Lite app are wide-ranging, and include:
* Serving the homepage, videos, exercise pages.
* Dealing with caching
* Administrative pages
and more!
"""
import sys
import traceback

from annoying.decorators import render_to
from annoying.functions import get_object_or_None

from django.contrib.auth import login as auth_login
from django.contrib.auth.models import User
from django.conf import settings; logging = settings.LOG
from django.contrib import messages
from django.core.urlresolvers import reverse
from django.http import HttpResponseNotFound, HttpResponseRedirect, HttpResponseServerError, HttpResponse
from django.template import RequestContext
from django.template.loader import render_to_string
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext as _

from fle_utils.internet.classes import JsonResponseMessageError
from fle_utils.internet.functions import get_ip_addresses, set_query_params
from kalite.i18n.base import outdated_langpacks, get_installed_language_packs
from kalite.shared.decorators.auth import require_admin
from kalite.topic_tools.content_models import search_topic_nodes
from securesync.api_client import BaseClient
from securesync.models import Device, SyncSession, Zone
from kalite.distributed.forms import SuperuserForm
from kalite.topic_tools.settings import CHANNEL
import json

from django.conf import settings
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)
from django.shortcuts import render_to_response

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils
from django.views.decorators.csrf import csrf_exempt
from django.contrib.messages.api import *
from django.contrib.messages.constants import *
from django.core.exceptions import PermissionDenied

def check_setup_status(handler):
    """
    Decorator for validating that KA Lite post-install setup has completed.
    NOTE that this decorator must appear before  the backend_cache_page decorator,
    so that it is run even when there is a cache hit.
    """
    def check_setup_status_wrapper_fn(request, *args, **kwargs):

        if "registered" not in request.session:
            logging.error("Key 'registered' not defined in session, but should be by now.")

        if request.is_admin:
            # TODO(bcipolli): move this to the client side?
            if not request.session.get("registered", True) and BaseClient().test_connection() == "success":
                # Being able to register is more rare, so prioritize.
                messages.warning(request, mark_safe(_("Please <a href='%s'>follow the directions to register your device</a>, so that it can synchronize with the central server.") % reverse("register_public_key")))
            elif not request.session["facility_exists"]:
                zone_id = (Zone.objects.all() and Zone.objects.all()[0].id) or "None"
                messages.warning(request, mark_safe(_("Please <a href='%s'>create a facility</a> now. Users will not be able to sign up for accounts until you have made a facility.") % reverse("add_facility", kwargs={"zone_id": zone_id})))

        elif not request.is_logged_in:
            if not request.session.get("registered", True) and BaseClient().test_connection() == "success":
                # Being able to register is more rare, so prioritize.
                redirect_url = reverse("register_public_key")
            elif not request.session["facility_exists"]:
                zone = Device.get_own_device().get_zone()
                zone_id = "None" if not zone else zone.id
                redirect_url = reverse("add_facility", kwargs={"zone_id": zone_id})
            else:
                redirect_url = None
            if redirect_url:
                messages.warning(request, mark_safe(
                    _("Please login with the admin account you created, then create your facility and register this device to complete the setup.")))

        if get_installed_language_packs()['en']['language_pack_version'] == 0:
            alert_msg = "<p>{}</p>".format(_(
                "Dear Admin, you need to download a full version of the English "
                "language pack for KA Lite to work."
            )) + "<p><a href=\"{url}\">{msg}</a></p>".format(
                url=reverse("update_languages"),
                msg=_("Go to Language Management")
            )
            alert_msg = mark_safe(alert_msg)
            messages.warning(
                request,
                alert_msg
            )
        else:
            outdated_langpack_list = list(outdated_langpacks())
            if outdated_langpack_list:
                pretty_lang_names = " --- ".join(lang.get("name", "") for lang in outdated_langpack_list)
                messages.warning(
                    request, _(
                        "Dear Admin, please log in and upgrade the following "
                        "languages as soon as possible: {}"
                    ).format(pretty_lang_names)
                )

        return handler(request, *args, **kwargs)
    return check_setup_status_wrapper_fn

@csrf_exempt
@render_to("distributed/learn.html")
def learn(request):
    """
    Render the all-in-one sidebar navigation/content-viewing app.
    """
    context = {
        "channel": CHANNEL,
        "pdfjs": settings.PDFJS,
    }
    return context


@csrf_exempt
@check_setup_status
@render_to("distributed/homepage.html")
def homepage(request):
    """
    Homepage.

    """

    return {}


def help(request):
    if request.is_admin:
        return help_admin(request)
    else:
        return help_student(request)


@require_admin
@render_to("distributed/help_admin.html")
def help_admin(request):
    context = {
        "wiki_url" : settings.CENTRAL_WIKI_URL,
        "ips": get_ip_addresses(include_loopback=False),
        "port": settings.USER_FACING_PORT,
    }
    return context


@render_to("distributed/help_student.html")
def help_student(request):

    context = {
        "wiki_url" : settings.CENTRAL_WIKI_URL,
    }
    return context


@require_admin
def zone_redirect(request):
    """
    Dummy view to generate a helpful dynamic redirect to interface with 'control_panel' app
    """
    device = Device.get_own_device()
    zone = device.get_zone()
    return HttpResponseRedirect(reverse("zone_management", kwargs={"zone_id": (zone and zone.pk) or "None"}))


@require_admin
def device_redirect(request):
    """
    Dummy view to generate a helpful dynamic redirect to interface with 'control_panel' app
    """
    device = Device.get_own_device()
    zone = device.get_zone()

    return HttpResponseRedirect(reverse("device_management", kwargs={"zone_id": (zone and zone.pk) or None, "device_id": device.pk}))

#SAML Changes



def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
    return auth

@csrf_exempt
def prepare_django_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    result = {
        'https': 'on' if request.is_secure() else 'off',
        'http_host': request.META['HTTP_HOST'],
        'script_name': request.META['PATH_INFO'],
        'server_port': request.META['SERVER_PORT'],
        'get_data': request.GET.copy(),
        'post_data': request.POST.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'query_string': request.META['QUERY_STRING']
    }
    return result

@csrf_exempt
def index(request):
    req = prepare_django_request(request)
    auth = init_saml_auth(req)

    request.session['user'] = {"is_admin": True, "is_logged_in": True, "is_teacher": True, "is_superuser": True,
                               "facility_user": "CharlO"}
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    paint_logout = False
    if 'sso' in req['get_data']:
        return HttpResponseRedirect(auth.login())
        # If AuthNRequest ID need to be stored in order to later validate it, do instead
        # sso_built_url = auth.login()
        # request.session['AuthNRequestID'] = auth.get_last_request_id()
        # return HttpResponseRedirect(sso_built_url)
    elif 'sso2' in req['get_data']:
        return_to = OneLogin_Saml2_Utils.get_self_url(req) + reverse('attrs')
        return HttpResponseRedirect(auth.login(return_to))
    elif 'slo' in req['get_data']:
        name_id = None
        session_index = None
        if 'samlNameId' in request.session:
            name_id = request.session['samlNameId']
        if 'samlSessionIndex' in request.session:
            session_index = request.session['samlSessionIndex']

        return HttpResponseRedirect(auth.logout(name_id=name_id, session_index=session_index))

        # If LogoutRequest ID need to be stored in order to later validate it, do instead
        # slo_built_url = auth.logout(name_id=name_id, session_index=session_index)
        # request.session['LogoutRequestID'] = auth.get_last_request_id()
        #return HttpResponseRedirect(slo_built_url)
    elif 'acs' in req['get_data']:
        request_id = None
        if 'AuthNRequestID' in request.session:
            request_id = request.session['AuthNRequestID']

        auth.process_response(request_id=request_id)
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        request.session['kalite_user_data'] = {"is_admin": True, "is_logged_in": True, "is_teacher": True, "is_superuser": True,
                                   "facility_user": "CharlO"}
        if not errors:
            if 'AuthNRequestID' in request.session:
                del request.session['AuthNRequestID']
            request.session['samlUserdata'] = auth.get_attributes()
            request.session['samlNameId'] = auth.get_nameid()
            request.session['samlSessionIndex'] = auth.get_session_index()
            request.session['kalite_user_data'] = auth.get_attribute("kalite_user_data")
            request.session['user'] = {"is_admin": True, "is_logged_in": True, "is_teacher": True, "is_superuser": True,
                                       "facility_user": "CharlO"}

            # TODO: instanciar el usuario como objeto de clase Facility.Model.FacilityUser.objects.filter
            #with open("/home/charlo/facility_user.txt",'w') as File:
            #   file.write(request.session['kalite_user_data'])

            if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                return HttpResponseRedirect(auth.redirect_to(req['post_data']['RelayState']))

    elif 'sls' in req['get_data']:
        request_id = None
        if 'LogoutRequestID' in request.session:
            request_id = request.session['LogoutRequestID']
        dscb = lambda: request.session.flush()
        url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return HttpResponseRedirect(url)
            else:
                success_slo = True

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()

    return render_to_response('index.html',
                              {'errors': errors,
                               'not_auth_warn': not_auth_warn,
                               'success_slo': success_slo,
                               'attributes': attributes,
                               'paint_logout': paint_logout},
                              context_instance=RequestContext(request))

@csrf_exempt
def attrs(request):
    paint_logout = False
    attributes = False

    if 'samlUserdata' in request.session:
        paint_logout = True
        if len(request.session['samlUserdata']) > 0:
            attributes = request.session['samlUserdata'].items()

    return render_to_response('attrs.html',
                              {'paint_logout': paint_logout,
                               'attributes': attributes},
                              context_instance=RequestContext(request))


@csrf_exempt
def metadata(request):
    # req = prepare_django_request(request)
    # auth = init_saml_auth(req)
    # saml_settings = auth.get_settings()
    saml_settings = OneLogin_Saml2_Settings(settings=None, custom_base_path=settings.SAML_FOLDER, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = HttpResponse(content=metadata, content_type='text/xml')
    else:
        resp = HttpResponseServerError(content=', '.join(errors))
    return resp



@render_to('distributed/search_page.html')
def search(request):
    # Inputs
    page = int(request.GET.get('page', 1))
    query = request.GET.get('query')
    max_results = request.GET.get('max_results', 50)

    # Outputs
    query_error = None
    possible_matches = {}
    hit_max = {}

    if query is None:
        query_error = _("Error: query not specified.")
        matches = []
        pages = 0

#    elif len(query) < 3:
#        query_error = _("Error: query too short.")

    else:
        query = query.lower()
        # search for topic, video or exercise with matching title

        matches, exact, pages = search_topic_nodes(query=query, language=request.language, page=page, items_per_page=max_results)

        if exact:
            # Redirect to an exact match
            return HttpResponseRedirect(reverse('learn') + matches[0]['path'])

    # Subdivide into categories.

    possible_matches = dict([(category, filter(lambda x: x.get("kind") == category, matches)) for category in set([x.get("kind") for x in matches])])

    previous_params = request.GET.copy()
    previous_params['page'] = page - 1

    previous_url = "?" + previous_params.urlencode()

    next_params = request.GET.copy()
    next_params['page'] = page + 1

    next_url = "?" + next_params.urlencode()

    return {
        'title': _("Search results for '%(query)s'") % {"query": (query if query else "")},
        'query_error': query_error,
        'results': possible_matches,
        'hit_max': hit_max,
        'more': pages > page,
        'page': page,
        'previous_url': previous_url,
        'next_url': next_url,
        'query': query,
        'max_results': max_results,
    }

def add_superuser_form(request):
    if request.method == 'GET':
        form = SuperuserForm()
        return_html = render_to_string('admin/superuser_form.html', {'form': form}, context_instance=RequestContext(request))
        data = {'Status' : 'ShowModal', 'data' : return_html}
        return HttpResponse(json.dumps(data), content_type="application/json")

def create_superuser(request):
    if request.method == 'POST':
        form = SuperuserForm(request.POST)
        if form.is_valid():
            # security precaution
            cd = form.cleaned_data
            superusername = cd.get('superusername')
            superpassword = cd.get('superpassword')
            confirmsuperpassword = cd.get('confirmsuperpassword')
            if superpassword != confirmsuperpassword:
                form.errors['confirmsuperpassword'] = form.error_class([_("Passwords don't match!")])
                return_html = render_to_string('admin/superuser_form.html', {'form': form}, context_instance=RequestContext(request))
                data = {'Status' : 'Invalid', 'data' : return_html}
            else:
                superemail = "superuser@learningequality.org"
                User.objects.create_superuser(username=superusername, password=superpassword, email=superemail)
                data = {'Status' : 'Success'}
        else:
            cd = form.cleaned_data
            if cd.get('confirmsuperpassword') != cd.get('superpassword'):
                form.errors['confirmsuperpassword'] = form.error_class([_("Passwords don't match!")])
            return_html = render_to_string('admin/superuser_form.html', {'form': form}, context_instance=RequestContext(request))
            data = {'Status' : 'Invalid', 'data' : return_html}

        return HttpResponse(json.dumps(data), content_type="application/json")

def crypto_login(request):
    """
    Remote admin endpoint, for login to a distributed server (given its IP address; see central/views.py:crypto_login)

    An admin login is negotiated using the nonce system inside SyncSession
    """
    if "client_nonce" in request.GET:
        client_nonce = request.GET["client_nonce"]
        try:
            session = SyncSession.objects.get(client_nonce=client_nonce)
        except SyncSession.DoesNotExist:
            return HttpResponseServerError("Session not found.")
        if session.server_device.is_trusted():
            user = get_object_or_None(User, username="centraladmin")
            if not user:
                user = User(username="centraladmin", is_superuser=True, is_staff=True, is_active=True)
                user.set_unusable_password()
                user.save()
            user.backend = "django.contrib.auth.backends.ModelBackend"
            auth_login(request, user)
        session.delete()
    return HttpResponseRedirect(reverse("homepage"))


def handler_403(request, *args, **kwargs):
    # context = RequestContext(request)
    # message = None  # Need to retrieve, but can't figure it out yet.

    if request.is_ajax():
        return JsonResponseMessageError(_("You must be logged in with an account authorized to view this page (API)."), status=403)
    else:
        messages.error(request, mark_safe(_("You must be logged in with an account authorized to view this page.")))
        return HttpResponseRedirect(set_query_params(reverse("homepage"), {"next": request.get_full_path(), "login": True}))


def handler_404(request):
    return HttpResponseNotFound(render_to_string("distributed/404.html", {}, context_instance=RequestContext(request)))


def handler_500(request):
    errortype, value, tb = sys.exc_info()
    context = {
        "request": request,
        "errormsg": settings.AJAX_ERROR,
        "errortype": errortype.__name__,
        "value": unicode(value),
        "traceback": traceback.format_exc(),
    }
    return HttpResponseServerError(render_to_string("distributed/500.html", context, context_instance=RequestContext(request)))
