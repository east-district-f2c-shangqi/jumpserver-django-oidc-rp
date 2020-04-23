"""
    OpenID Connect relying party (RP) app config
    ============================================

    This module contains the application configuration class - available in the Django app registry.
    For more information on this file, see https://docs.djangoproject.com/en/dev/ref/applications/

"""

from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _


class JumpServerOIDCRelyingPartyAppConfig(AppConfig):
    label = 'jms_oidc_rp'
    name = 'jms_oidc_rp'
    verbose_name = _('JumpServer OpenID Connect relying party')
