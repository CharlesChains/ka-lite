"""
"""
from annoying.functions import get_object_or_None

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404
from django.utils.translation import ugettext as _

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings
from onelogin.saml2.utils import OneLogin_Saml2_Utils

from kalite.facility.decorators import facility_from_request
from kalite.facility.models import FacilityUser
from securesync.models import Device, Zone


def get_user_from_request(handler=None, request=None, *args, **kwargs):
    """
    Gets ID of requested user (not necessarily the user logged in)
    """
    assert handler or request
    if not handler:
        handler = lambda request, user, *args, **kwargs: user

    def get_user_from_request_wrapper_fn(request, *args, **kwargs):
        user = get_object_or_None(FacilityUser, id=request.REQUEST["user"]) if "user" in request.REQUEST else None  # don't hit DB if we don't have to
        user = user or request.session.get("facility_user")
        return handler(request, *args, user=user, **kwargs)
    return get_user_from_request_wrapper_fn if not request else get_user_from_request_wrapper_fn(request=request, *args, **kwargs)

def require_login(handler):
    """
   (Level 1) Make sure that a user is logged in to the distributed server.
    """
    """"#Replaced with PySaml authentication
    def require_login_wrapper_fn(request, *args, **kwargs):
        if getattr(request, "is_logged_in", False):  # requires the securesync.middleware.AuthFlags middleware be hit
            return handler(request, *args, **kwargs)

        # Failed.  Send different response for ajax vs non-ajax requests.
        raise PermissionDenied(_("You must be logged in to access this page."))
    return require_login_wrapper_fn
    """

    def prepare_django_request(request):
        result = {
            'https': 'on' if request.is_secure() else 'off',
            'http_host': request.META['HTTP_HOST'],
            'script_name': request.META['PATH_INFO'],
            'server_port': request.META['SERVER_PORT'],
            #'get_data': request.GET.copy(),
            'SAMLRequest': 'eJzNWEuTo7yS/UG9EWAqmmVjIww2ciH0AO0AeQqDwLQLG8yvn3S/vr437kzMciK8sS2lMlMnTx7l+87bVHL+0L141rZ5VC26JNlmjtqvX3bp9Wtt46naf3tLc4HK0M1Uji2VExQFJnjP4v+qB4LIjtvRxY8rE5va8R/VQIwIv3qR8ZqiT5akTS6wfq0dYTLprjrEd72Dc9pvC9mi+ZShhVjpM2HXmbTXFVZ/iL/9ubz82ZDt5dvH+540lVzmkyGoyKlVrz9/j7bf/vjKHdrovVhT2+tU5stCLpZi6KLz+H7qvQbsrqfeBTtiPQ20BVs+4/Pb65zT8NvuyLQkLcS6RpcfufiIdvPj3894/0CHP2fvxu6Vm1K6LxtjZW++/Nnzz3+NDl9x/R3P/FbCOVqK53vfIL3319Pl66PI/fnYe3cll4eyzf3Yk0eVeWshrc+jbRnIYwfnNMe1cJI2tcj656yxdgjcU/TL7+XHnlNPTD2kXxg3MeUkSBHxdUeGNNdx2uEhE0KegyWvQtKdWHPJ5FSmyHNri74rZF2PljmcsHAoxirrpofszFX35JQKjGkXU7Ajzp1IGMc3ioJFcLEtA2snjCLngLylfNwq5Eo46/FakxlKuAF7uVYUK8r5EqR5kxa9JZmMnmrvX0oeH2Sn/DPgLZXi937CeDGfclGKvLFlG39qbjDtR5W03VL0LgV/ecoEEUHwZDxCMqCcMkIoNi7jFCfIestycxK9V1BM4zO3ApkbWM9Xlo/w3ZWV8/81HgP3Zb6n3N0qe1rKcBrpapwkiH3ORZhy/J4iTE8BJhk329TWx9d3yrFTOMTWrHBoK3jlxFvSLSdiXW88wHc+pK7ci55gelD9iEheP+kK+xhp5MA3pe2G5yFOMqamU04+M3N9ZPvYPWEVKOlZRa8OctcgaUjDEY7PgeZ1CzW0J3fV43dt40H1zcxbnbIQT8Iet7JfCpGPud75axVGGybVQ3DvdA68m9zpQ91DjC2NGJ+OtdCMPCeWCH3LHDVk+2im3C14p1KyiisV6gG1dWUDHsrhamlBhrqbDLUXSUOaJCh+J0Hs1lJfZDAlZa4chixD5LgphPKr53QvBX1mwjwBAygZ/EkE+qryZlMZ/kw6j2S5/73oGvtgT6Xqpu8VHrsK4iqdODwi3fIwRVrQU5U3a7VXDVDbKORkVKjjbKCc5c0n7wguOxVRk7iQB1cHKtVW8xTd5BYDxG/oo8T6PWFkZYGbnVvlq9xc01XIgo9YCxzTANOUxw8SNBzwEHFu+RppPxGiA/zh9OI5nBMCWHAyqFfAY5YE3jY1gKuuOQnbW4QTOUc0RmL9WGtJMe/jqerxTjHsVtyKqYV/4DPDUDdSK+XoQQrt/5/2S08qOUkRxJwJvGoEJjh8BN6DfwdhxBvlC0nltE8ZFsBHw2tNFVgbaqgP+wZm1DbN4eyAu1qM4rxXZdIvVsbFZ2mJAHwiaUt/7ccO5JAnrfgUQe2CHzkJNRXI/V60RGpJd1CLhIbTBuq/SZEKCytZatxEqlf7Mx/3XI5r3Ym3CtFYtfFOdYqk7Kd9FVCH8uihLYxffJmFOviP9Sf+qT/wqSTILZjUQvfBDNiwqpA7tbQORU4eZKcmgT43tRSQW4pT0/SK42OS04mLxK266ZauZOHA+yfs34mgW50Dpiz6YOF0YaZxpBGCCfquu8gpLGrptrm84MFYs4rA9dWK0zpILc6aPuXWodp3cyk9VvOPJRH+qViNKftXnumJ7v39WQio86bUbTBDre2TIY75oJ2CkZnLpWMOjtlAQnWZgFqiOemtpbbqh94Vy4mJgxgwyoL4ewp9qMYfc2GbT9nH+dGub7Uc7QRFbmbV9kmOOUfWZ+EYVO/jVmKylgh4w46dem8eak970vInYRRILy7Opnmm/bwmiK40xE0iXS66GeLC5QFNA0WeTRw9nwLXlWGxEofcSefdU86dQuDvik+Y76EmESCBW4JZ472WwCGdhxPmnyRf8hNfbqntcj18QzSYorLDo2S6P+PAe2d/eitoghj9W9+/qbz72VdzsMljH+rzlPYaYm5uJa9dvfrbn30S+xyRbWZrRwETlwgDK2C/Qub1f8Acsk2QUUrym9r5jxTOKTohExxvXj1bBEQk/XgXVjxkoXmD3pwlXWDBvQQJVEFlpy7vu1UgPRKjj2VgZNLrN8CxKpG1B06YNPLMcUYHOSRPPUSz6GqnypWpDZ8rJqBDuDva+iXfqUvBvTvoIF8ORFTW6GfcVdw0edXiVYXWklra0dy6pLYIk61nCPirglFWSGR8xTbbFTd++ero1r/z3kqS1R8PNmapCdZKUv8s/G3Nxxvh3oX05lYh95p1Ks72I9TPfKvbwJLZ12fyDfzF/sBCKwV8hlnQoAybvjBiBA0j0949HRA+1ihuqQQsYQFcVy/UGLDrJXI/IrqLZfbSTTa5MKYZYIqlkAc9KMTzj/XE1U73yUwhVqifw0k0m7SzHjoYj3IYxwrqTMrlSVm0qblQmVCo6JbnWSZOyoNFcXcVmCS1PVEFeQAtgM8GUBw2PvTvLfAChl4M9x37mTWWWffhUt7QavXLlOtPFjS3wmBZWz5ojyZPnPjOt9MdaulNhejGgNmrFOyGk9BoeVcD6YrO63QueL1+m0VLdgknsw7qpeTTlQTL/WgvLrMbAf0V7oycSmHA12nmuUnYigMpx6lm5vMM/upOuGWgvleCfNbcu0FedolFLsQeNwmCLm7GY8aagnCgJ6NmvQYrl0RBzXYlEpcscO9iRwZie4dCgP7Nr6sAf2tOn+egnutVPeFurWxnlBTUzvoPlHa0KxlpU0ffKdpsxNMzgD2X5IAbQ3E2JA+FcaItcdStCGWgP5OOHvQPPCS2QEuaISulgWZaxHPaNvIkzHcVxgnvLJEFitbCt4ndXCpUWDqnioRexMKlZ3KE/r9AjftH2ZPNiZtPAv4WwJ3lHt+lRHYtGn4KrFUZ31f7JhUheVNB81DZtCdotqD304x/PGReo1cPgwbnEwtfCdf8vNchGQQ9Y7/TYFfDuXoXuayF3Et3n9mNX9kCeoTIk8zb8c4ceeun9Z7fQCNBfCnoK0qyzs3ZvlFZ70GcsX/urDdm+UvWQm3DvVUXLwKsRZLPazbojLDI0V1h87y+yVy8q45EOnAPgIk7c2JUcvMA3n8/yQiwQIKkpdeyiyXrBFKO4SQ08gz+ZiuUuyMeBVNrDd206puI9HQoVrVkwWgSywe+BK3Lg/Xce4d0pTw1cXSWZDigEWKsn2UXPRL8uhMOvW/hHPzNhkYqlCxs4HNx8QhwwkqMMppfnwxNBvTvvhTX5zmMgyywHhL4+rz9dMh+fDta2D86H4+Um/ek/1jgTfWsw81PnEl9B91CwNKdM3qDGmu1rUvQgxe5E3fFuw3cJWWygLr2rKP96u2pXUvXPkCtnZm/kb2rSsu3qxw/MjQOrzywPdQ69q/Eoiq1p52yDE6ZL05MxbTV7xLHowhBs2PQ5uECNYVXzunt3CuaWRreDmJfd8EsWHNKOhdiF6wC/IL+7aoQbNveJjHmlA4fTmaLpAzip+QNvExBV3XXWxaYRGOVgNaNdRAtGZpSZuE5g/cf3wEeWr+T8vNxtHWUgL+gExAPxiszOKqHbw8pxp6vcVABZ5JcD5x7MdzjsWSNyXpDNBb3sv1A8B6KCfLakqczyTxXXKCnBuIVr6/h3o4WCQ4ONqTTN9hvsT1NdDitkJ8nsT8tyAfkzQf+EQcWIPA7ZuWOgtZv3kvevEk+uRQ0WL0WD4pUXnZjyoF/RaBQvcafysT9wVJZJYFz7Xiu2vi9vHigH4w6oqvNd7gohbILQ5uEC/TiSOD76zmn17QP4E6xWyCDACetePWhbixYp1m2w5yA5gAN45ZGWZUYQwG6n7JkZd0Ysh1oawMaPgxWIqGeUTykg+kJi3HZL9eSRysPaQk4n2u4NyanWTHV01ABBjdLHYzqxceZUbcEOB/6cyGcZEMFHivZ2YnB99ICnfz86pQ9dsvebTMsbrTFn/COm6lj7vWr3jo6wzs0qXscnQfRgea9JqxDpYVBp6oT7+gz2RkEeQlJ3m1q2wRl7iOIL6PM50o209GebozhCd5CN9lb1wryW+YJaMhklqCC1V5HFOFAb72WhfET+B2/b71f84HJnNm/ziVAf68vvQOa8f575nPem7fT7mPzmvn8mDNw8N+hTTWkXtSCJmTplOy6KWEa9HjwluyKt2SNLhEGjTGQ11zkte6ebH/NJ7Z/n0dR3ZsL8LT5MWMJxaSk+1tv/Y9ro+A1z+Fe1IupkObz97zof9sjevypJf9SyGUsbPGtkGRSmdXCu3g+9vF4bv9oPl/v6bOUsQX+/Jon/WV/95/W8X9i+53fDiO9j8diAJ4VP+ZMppLirne/cv7PurW2xfPPnKj9a+7Ui7UOvXtt8y//DdKplkU=',
            #'SAMLRequest': request.GET['SAMLRequest'],
            #'post_data': request.POST.copy(),
            # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
            # 'lowercase_urlencoding': True,
            'query_string': request.META['QUERY_STRING']
        }
        return result

    def require_login_wrapper_fn(request, *args, **kwargs):

        req = prepare_django_request(request)
        cwd = '/home/charlo/Documents/KALITE/'
        file = cwd + "/temp231.txt"
        reque = ""
        import json
        with open(file, 'w') as f:
            f.write(json.dumps(req))
        auth = OneLogin_Saml2_Auth(req, custom_base_path=settings.SAML_FOLDER)
        auth.login()
        auth.build_request_signature(req,"http://0.0.0.0:8008")
        import pdb;
        pdb.set_trace()
        auth.process_respgonse(req)
        errors = auth.get_errors()
        if not errors:
            if auth.is_authenticated():
                request.session['samlUserdata'] = auth.get_attributes()
                if 'RelayState' in req['post_data'] and OneLogin_Saml2_Utils.get_self_url(req) != req['post_data']['RelayState']:
                    auth.redirect_to(req['post_data']['RelayState'])
                else:
                    for attr_name in request.session['samlUserdata'].keys():
                        print '%s ==> %s' % (attr_name, '|| '.join(request.session['samlUserdata'][attr_name]))
            else:
                print "Not Authenticated"
                raise PermissionDenied(_("You must be logged in to access this page."))
        else:
            print "Error when processing SAML Response: %s" % (', '.join(errors))
    return require_login_wrapper_fn


def require_admin(handler):
    """
    Level 2: Require an admin:
    * Central server: any user with an account
    * Distributed server: any Django admin or teacher.

    Note: different behavior for api_request or not
    Note2: we allow users to 'access themselves'
    """

    @require_login
    def require_admin_wrapper_fn(request, *args, **kwargs):
        if (settings.CENTRAL_SERVER and request.user.is_authenticated()) or getattr(request, "is_admin", False):
            return handler(request, *args, **kwargs)

        # Allow users to edit themselves
        facility_user_id = kwargs.get("facility_user_id")
        if request.session.get('facility_user') and facility_user_id == request.session.get('facility_user').id:
            return handler(request, *args, **kwargs)

        # Only here if user is not authenticated.
        # Don't redirect users to login for an API request.
        raise PermissionDenied(_("You must be logged in as an admin to access this page."))

    return require_admin_wrapper_fn


def require_authorized_access_to_student_data(handler):
    """
    WARNING: this is a crappy function with a crappy name.

    This should only be used for limiting data access to single-student data.

    Students requesting their own data (either implicitly, without querystring params)
    or explicitly (specifying their own user ID) get through.
    Admins and teachers also get through.
    """
    if settings.CENTRAL_SERVER:
        return require_authorized_admin(handler)

    else:
        @require_login
        def require_authorized_access_to_student_data_wrapper_fn_distributed(request, *args, **kwargs):
            """
            Everything is allowed for admins on distributed server.
            For students, they can only access their own account.
            """
            if getattr(request, "is_admin", False):
                return handler(request, *args, **kwargs)
            else:
                user = get_user_from_request(request=request)
                if request.session.get("facility_user") == user:
                    return handler(request, *args, **kwargs)
                else:
                    raise PermissionDenied(_("You requested information for a user that you are not authorized to view."))
            return require_admin(handler)
        return require_authorized_access_to_student_data_wrapper_fn_distributed


def require_authorized_admin(handler):
    """
    Level 1.5 or 2.5 :) : require an admin user that has access to all requested objects.

    Central server: this is by organization permissions.
    Distributed server: you have to be an admin (Django admin/teacher), or requesting only your own user data.

    For testing purposes:
    * distributed server: superuser, teacher, student
    * central server: device not on zone/org, facility not on zone/org, zone not in org, zone with one org, zone with multi orgs, etc
    """

    @require_admin
    def require_authorized_admin_wrapper_fn_central(request, *args, **kwargs):
        """
        The check for distributed servers already exists (require_login), so just use that below.
        All this nuance is for the central server only.
        """
        # inline import, to avoid unnecessary dependency on central server module
        #    on the distributed server.
        from centralserver.central.models import Organization

        logged_in_user = request.user
        assert not logged_in_user.is_anonymous(), "Wrapped by login_required!"

        # Take care of superusers (Django admins).
        if logged_in_user.is_superuser:
            return handler(request, *args, **kwargs)


        # Objects we're looking to verify
        org = None
        org_id = kwargs.get("org_id")
        zone = None
        zone_id = kwargs.get("zone_id")
        facility = facility_from_request(request=request, *args, **kwargs)
        device = None
        device_id = kwargs.get("device_id")
        user = get_user_from_request(request=request, *args, **kwargs)

        # Validate user through facility
        if user:
            if not facility:
                facility = user.facility

        # Validate device through zone
        if device_id:
            device = get_object_or_404(Device, pk=device_id)
            if not zone_id:
                zone = device.get_zone()
                if not zone:
                    raise PermissionDenied(_("You requested device information for a device without a sharing network.  Only super users can do this!"))
                zone_id = zone.pk

        # Validate device through zone
        if facility:
            if not zone_id:
                zone = facility.get_zone()
                if not zone:
                    raise PermissionDenied(_("You requested facility information for a facility with no sharing network.  Only super users can do this!"))
                zone_id = zone.pk

        # Validate zone through org
        if zone_id and zone_id != "new":
            zone = get_object_or_404(Zone, pk=zone_id)
            if not org_id:
                # Have to check if any orgs are accessible to this user.
                for org in Organization.from_zone(zone):
                    if org.is_member(logged_in_user):
                        return handler(request, *args, **kwargs)
                raise PermissionDenied(_("You requested information from an organization that you're not authorized on."))

        if org_id and org_id != "new":
            org = get_object_or_404(Organization, pk=org_id)
            if not org.is_member(logged_in_user):
                raise PermissionDenied(_("You requested information from an organization that you're not authorized on."))
            elif zone_id and zone and org.zones.filter(pk=zone.pk).count() == 0:
                raise PermissionDenied(_("This organization is not linked to the requested sharing network."))

        # Made it through, we're safe!
        return handler(request, *args, **kwargs)

    # This is where the actual distributed server check is done (require_admin)
    return require_authorized_admin_wrapper_fn_central if settings.CENTRAL_SERVER else require_admin(handler)


def require_superuser(handler):
    """
    Level 4: require a Django admin (superuser)

    ***
    *** Note: Not yet used, nor tested. ***
    ***

    """
    def require_superuser_wrapper_fn(request, *args, **kwargs):
        if getattr(request.user, "is_superuser", False):
            return handler(request, *args, **kwargs)
        else:
            raise PermissionDenied(_("You must be logged in as a superuser to access this endpoint."))
    return require_superuser_wrapper_fn
