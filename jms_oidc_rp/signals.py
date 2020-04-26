"""
    OpenID Connect relying party (RP) signals
    =========================================

    This modules defines Django signals that can be triggered during the OpenID Connect
    authentication process.

"""

from django.dispatch import Signal


oidc_user_created = Signal(providing_args=['request', 'oidc_user'])
oidc_user_updated = Signal(providing_args=['request', 'oidc_user'])
oidc_user_login_success = Signal(providing_args=['request', 'user'])
oidc_user_login_failed = Signal(providing_args=['username', 'request', 'reason'])

