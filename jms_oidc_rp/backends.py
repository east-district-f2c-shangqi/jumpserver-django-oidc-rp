"""
    OpenID Connect relying party (RP) authentication backends
    =========================================================

    This modules defines backends allowing to authenticate a user using a specific token endpoint
    of an OpenID Connect provider (OP).

"""

import requests
from rest_framework.exceptions import ParseError
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.core.exceptions import SuspiciousOperation
from django.db import transaction
from django.urls import reverse

from .conf import settings as oidc_rp_settings
from .models import OIDCUser
from .utils import validate_and_return_id_token
from .decorator import ssl_verification
from .signals import (
    openid_user_create_or_update, openid_user_login_failed, openid_user_login_success
)


class ActionForUser:

    @transaction.atomic
    def get_or_create_user_from_claims(self, request, claims):
        sub = claims['sub']
        name = claims.get('name', sub)
        username = claims.get('preferred_username', sub)
        email = claims.get('email', "{}@{}".format(username, 'jumpserver.openid'))
        user, created = get_user_model().objects.get_or_create(
            username=username, defaults={"name": name, "email": email}
        )
        openid_user_create_or_update.send(
            sender=self.__class__, request=request, user=user, created=created,
            name=name, username=username, email=email
        )
        return user, created

    @staticmethod
    @transaction.atomic
    def update_or_create_oidc_user(user, claims):
        sub = user.oidc_user.sub if hasattr(user, 'oidc_user') else claims['sub']
        oidc_user, created = OIDCUser.objects.update_or_create(
            sub=sub, defaults={'user': user, 'userinfo': claims}
        )
        return oidc_user


class OIDCAuthCodeBackend(ActionForUser, ModelBackend):
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
        try:
            token_response_data = token_response.json()
        except Exception as e:
            error = "OIDCAuthCodeBackend token response json error, token response " \
                    "content is: {}, error is: {}".format(token_response.content, str(e))
            raise ParseError(error)

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
        # https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        if oidc_rp_settings.ID_TOKEN_INCLUDE_CLAIMS:
            claims = id_token
        else:
            # Fetches the claims (user information) from the userinfo endpoint provided by the OP.
            claims_response = requests.get(
                oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
                headers={'Authorization': 'Bearer {0}'.format(access_token)}
            )
            claims_response.raise_for_status()
            try:
                claims = claims_response.json()
            except Exception as e:
                error = "OIDCAuthCodeBackend claims response json error, claims response " \
                        "content is: {}, error is: {}".format(claims_response.content, str(e))
                raise ParseError(error)

        user, created = self.get_or_create_user_from_claims(request, claims)
        self.update_or_create_oidc_user(user, claims)
        return user


class OIDCAuthPasswordBackend(ActionForUser, ModelBackend):

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

        # Calls the token endpoint.
        token_response = requests.post(oidc_rp_settings.PROVIDER_TOKEN_ENDPOINT, data=token_payload)
        try:
            token_response_data = token_response.json()
        except Exception as e:
            error = "OIDCAuthPasswordBackend token response json error, token response " \
                    "content is: {}, error is: {}".format(token_response.content, str(e))
            print(error)
            openid_user_login_failed.send(
                sender=self.__class__, request=request, username=username, reason=error
            )
            return

        # Retrieves the access token
        access_token = token_response_data.get('access_token')

        # Fetches the claims (user information) from the userinfo endpoint provided by the OP.
        claims_response = requests.get(
            oidc_rp_settings.PROVIDER_USERINFO_ENDPOINT,
            headers={'Authorization': 'Bearer {0}'.format(access_token)}
        )
        try:
            claims = claims_response.json()
        except Exception as e:
            error = "OIDCAuthPasswordBackend claims response json error, claims response " \
                    "content is: {}, error is: {}".format(claims_response.content, str(e))
            print(error)
            openid_user_login_failed.send(
                sender=self.__class__, request=request, username=username, reason=error
            )
            return

        user, created = self.get_or_create_user_from_claims(request, claims)
        self.update_or_create_oidc_user(user, claims)
        openid_user_login_success.send(sender=self.__class__, request=request, user=user)
        return user
