"""TcEx Framework Module"""
# standard library
import logging
from functools import cached_property

from ..app.config.install_json import InstallJson
from ..input.model.module_requests_session_model import ModuleRequestsSessionModel
from ..pleb.proxies import proxies
from ..pleb.registry import registry
from ..pleb.scoped_property import scoped_property
from .auth.hmac_auth import HmacAuth
from .auth.tc_auth import TcAuth
from .auth.token_auth import TokenAuth
from .external_session import ExternalSession
from .tc_session import TcSession

# get logger
_logger = logging.getLogger(__name__.split('.', maxsplit=1)[0])


class RequestsSession:
    """Requests Session Class"""

    def __init__(self, model: ModuleRequestsSessionModel):
        """Initialize instance properties."""
        self.model = model

        # properties
        self.install_json = InstallJson()
        self.log = _logger

    @cached_property
    def external(self) -> ExternalSession:
        """Return an instance of Requests Session configured for the ThreatConnect API."""
        return self.get_session_external()

    def get_session_external(self, log_curl: bool = True) -> ExternalSession:
        """Return an instance of Requests Session configured for the ThreatConnect API."""
        _session_external = ExternalSession()

        # add User-Agent to headers
        _session_external.headers.update(registry.app.user_agent)

        # add proxy support if requested
        if self.model.tc_proxy_external:
            _session_external.proxies = self.proxies
            self.log.info(
                f'Using proxy host {self.model.tc_proxy_host}:'
                f'{self.model.tc_proxy_port} for external session.'
            )

        if self.model.tc_log_curl:
            _session_external.log_curl = log_curl

        return _session_external

    def get_session_tc(
        self,
        auth: HmacAuth | TokenAuth | TcAuth | None = None,
        base_url: str | None = None,
        log_curl: bool | None = None,
        proxies: dict[str, str] | None = None,  # pylint: disable=redefined-outer-name
        proxies_enabled: bool | None = None,
        verify: bool | str | None = None,
    ) -> TcSession:
        """Return an instance of Requests Session configured for the ThreatConnect API.

        No args are required to get a working instance of TC Session instance.

        This method allows for getting a new instance of TC Session instance. This can be
        very useful when connecting between multiple TC instances (e.g., migrating data).
        """
        if log_curl is None:
            log_curl = self.model.tc_log_curl

        if proxies_enabled is None:
            proxies_enabled = self.model.tc_proxy_tc

        if verify is None:
            verify = self.model.tc_verify

        tc_token = None
        # 1. if token module is available, use token callback
        # 2. if token is set in the model, use that (no renewal)
        # 3. no token is not available, use api credentials
        if not hasattr(registry.app, 'token') and self.install_json.is_external_app is False:
            tc_token = registry.app.token.get_token
        elif self.model.tc_token is not None:
            tc_token = self.model.tc_token

        auth = auth or TcAuth(
            tc_api_access_id=self.model.tc_api_access_id,
            tc_api_secret_key=self.model.tc_api_secret_key,
            tc_token=tc_token,
        )

        return TcSession(
            auth=auth,
            base_url=base_url or self.model.tc_api_path,
            log_curl=log_curl,
            proxies=proxies or self.proxies,
            proxies_enabled=proxies_enabled,
            user_agent=registry.app.user_agent,
            verify=verify,
        )

    @cached_property
    def proxies(self) -> dict:
        """Return proxies dictionary for use with the Python Requests module."""
        return proxies(
            proxy_host=self.model.tc_proxy_host,
            proxy_port=self.model.tc_proxy_port,
            proxy_user=self.model.tc_proxy_username,
            proxy_pass=self.model.tc_proxy_password,
        )

    @scoped_property
    def tc(self) -> TcSession:
        """Return an instance of Requests Session configured for the ThreatConnect API."""
        return self.get_session_tc()
