"""
    OpenID Connect relying party (RP) authentication backends
    =========================================================

    This modules defines backends allowing to authenticate a user using a specific token endpoint
    of an OpenID Connect provider (OP).

"""

import requests
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.urls import reverse
from django.utils.encoding import smart_text

from .conf import settings as oidc_rp_settings
from .models import OIDCUser
from .signals import (
    oidc_user_created, oidc_user_updated, oidc_user_login_success, oidc_user_login_failed
)
from .utils import validate_and_return_id_token
from .decorator import ssl_verification


class OIDCAuthCodeBackend(ModelBackend):
    """ Allows to authenticate users using an OpenID Connect Provider (OP).

    This authentication backend is able to authenticate users in the case of the OpenID Connect
    Authorization Code flow. The ``authenticate`` method provided by this backend is likely to be
    called when the callback URL is requested by the OpenID Connect Provider (OP). Thus it will
    call the OIDC provider again in order to request a valid token using the authorization code that
    should be available in the request parameters associated with the callback call.

    """

    @ssl_verification
    def authenticate(self, request, nonce=None, **kwargs):
        """ Authenticates users in case of the OpenID Connect Authorization code flow. """
        # NOTE: the request object is mandatory to perform the authentication using an authorization
        # code provided by the OIDC supplier.
        if (nonce is None and oidc_rp_settings.USE_NONCE) or request is None:
            return

        # Fetches required GET parameters from the HTTP request object.
        state = request.GET.get('state')
        code = request.GET.get('code')

        # Don't go further if the state value or the authorization code is not present in the GET
        # parameters because we won't be able to get a valid token for the user in that case.
        if (state is None and oidc_rp_settings.USE_STATE) or code is None:
            raise SuspiciousOperation('Authorization code or state value is missing')

        # Prepares the token payload that will be used to request an authentication token to the
        # token endpoint of the OIDC provider.
        token_payload = {
            'client_id': oidc_rp_settings.CLIENT_ID,
            'client_secret': oidc_rp_settings.CLIENT_SECRET,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': request.build_absolute_uri(
                reverse(oidc_rp_settings.AUTH_LOGIN_CALLBACK_URL_NAME)
            ),
        }

        # Calls the token endpoint.
        token_response = requests.post(oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT, data=token_payload)
        token_response.raise_for_status()
        token_response_data = token_response.json()

        # Validates the token.
        raw_id_token = token_response_data.get('id_token')
        id_token = validate_and_return_id_token(raw_id_token, nonce)
        if id_token is None:
            return

        # Retrieves the access token and refresh token.
        access_token = token_response_data.get('access_token')
        refresh_token = token_response_data.get('refresh_token')

        # Stores the ID token, the related access token and the refresh token in the session.
        request.session['oidc_auth_id_token'] = raw_id_token
        request.session['oidc_auth_access_token'] = access_token
        request.session['oidc_auth_refresh_token'] = refresh_token

        # If the id_token contains userinfo scopes and claims we don't have to hit the userinfo
        # endpoint.
        if oidc_rp_settings.ID_TOKEN_INCLUDE_USERINFO:
            userinfo_data = id_token
        else:
            # Fetches the user information from the userinfo endpoint provided by the OP.
            userinfo_response = requests.get(
                oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
                headers={'Authorization': 'Bearer {0}'.format(access_token)})
            userinfo_response.raise_for_status()
            userinfo_data = userinfo_response.json()

        oidc_user, created = create_or_update_oidc_user(userinfo_data)
        if created:
            oidc_user_created.send(sender=self.__class__, request=request, oidc_user=oidc_user)
        else:
            oidc_user_updated.send(sender=self.__class__, request=request, oidc_user=oidc_user)

        return oidc_user.user


class OIDCAuthPasswordBackend(ModelBackend):

    @ssl_verification
    def authenticate(self, request, username=None, password=None, **kwargs):
        """
        https://oauth.net/2/
        https://aaronparecki.com/oauth-2-simplified/#password
        """

        if not username or not password:
            return

        # Prepares the token payload that will be used to request an authentication token to the
        # token endpoint of the OIDC provider.
        token_payload = {
            'client_id': oidc_rp_settings.CLIENT_ID,
            'client_secret': oidc_rp_settings.CLIENT_SECRET,
            'grant_type': 'password',
            'username': username,
            'password': password,
        }

        token_response = requests.post(oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT, data=token_payload)
        try:
            token_response.raise_for_status()
        except Exception as e:
            print('OIDCAuthPasswordbackend error: {}'.format(e))
            reason = "OpenID error authenticating user password"
            oidc_user_login_failed.send(
                sender=self.__class__, usesrname=username, request=request, reason=reason
            )
            return
        else:
            token_response_data = token_response.json()

        access_token = token_response_data.get('access_token')

        userinfo_response = requests.get(
            oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
            headers={'Authorization': 'Bearer {0}'.format(access_token)})
        userinfo_data = userinfo_response.json()

        oidc_user, created = create_or_update_oidc_user(userinfo_data)
        if created:
            oidc_user_created.send(sender=self.__class__, request=request, oidc_user=oidc_user)
        else:
            oidc_user_updated.send(sender=self.__class__, request=request, oidc_user=oidc_user)

        oidc_user_login_success.send(sender=self.__class__, request=request, user=oidc_user.user)
        return oidc_user.user


def get_or_create_user(name, username, email):
    username = smart_text(username)

    users = get_user_model().objects.filter(username=username)

    if len(users) == 0:
        user = get_user_model().objects.create_user(username=username, email=email, name=name)
    elif len(users) == 1:
        return users[0]
    else:  # duplicate handling
        current_user = None
        for u in users:
            current_user = u
            if hasattr(u, 'oidc_user'):
                return u

        return current_user

    return user


def get_userinfo_from_claims(claims):
    """
    returrn: (name, username, email)
    """
    # Get username from claims
    username = None
    if oidc_rp_settings.PROVIDER_CLAIMS_USERNAME is not None:
        username = claims.get(oidc_rp_settings.PROVIDER_CLAIMS_USERNAME)
    else:
        username_possible_key_names = ['preferred_username', 'id']
        for username_key_name in username_possible_key_names:
            username = claims.get(username_key_name)
            if username is not None:
                break

    # Get email from claims
    if oidc_rp_settings.PROVIDER_CLAIMS_EMAIL is not None:
        email = claims.get(oidc_rp_settings.PROVIDER_CLAIMS_EMAIL)
    else:
        email = claims.get('email')
    if not email:
        email = '{}@{}'.format(username, 'jumpserver.oidc')

    # Get name from claims
    name = None
    if oidc_rp_settings.PROVIDER_CLAIMS_NAME is not None:
        name = claims.get(oidc_rp_settings.PROVIDER_CLAIMS_NAME)
    else:
        name_possible_key_names = ['name', 'id', 'preferred_username']
        for name_key_name in name_possible_key_names:
            name = claims.get(name_key_name)
            if name is not None:
                break
    if not name:
        name = username

    return name, username, email


@transaction.atomic
def create_oidc_user_from_claims(claims):
    """
    Creates an ``OIDCUser`` instance using the claims extracted from an id_token.
    https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
    """
    # Get sub value from claims
    sub = None
    sub_possible_key_names = ['sub', 'id']
    for sub_key_name in sub_possible_key_names:
        sub = claims.get(sub_key_name)
        if sub is not None:
            break

    name, username, email = get_userinfo_from_claims(claims)
    user = get_or_create_user(name, username, email)
    if hasattr(user, 'oidc_user'):
        update_oidc_user_from_claims(user.oidc_user, claims)
        oidc_user = user.oidc_user
    else:
        oidc_user = OIDCUser.objects.create(user=user, sub=sub, userinfo=claims)

    return oidc_user


@transaction.atomic
def update_oidc_user_from_claims(oidc_user, claims):
    """ Updates an ``OIDCUser`` instance using the claims extracted from an id_token. """
    oidc_user.userinfo = claims
    oidc_user.save()


def create_or_update_oidc_user(userinfo_data):
    """
    Tries to retrieve a corresponding user in the local database and creates it if applicable.
    """
    try:
        oidc_user = OIDCUser.objects.select_related('user').get(sub=userinfo_data.get('sub'))
    except OIDCUser.DoesNotExist:
        created = True
        oidc_user = create_oidc_user_from_claims(userinfo_data)
    else:
        created = False
        update_oidc_user_from_claims(oidc_user, userinfo_data)

    return oidc_user, created
