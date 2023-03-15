"""ThreatConnect HMAC Authorization"""
# standard library
import time
from collections.abc import Callable

# third-party
from requests import Request  # TYPE-CHECKING
from requests import auth

from ...app.token import Token  # type: ignore # pylint: disable=import-error
from ...input.field_type.sensitive import Sensitive  # type: ignore # pylint: disable=import-error


class TokenAuth(auth.AuthBase):
    """ThreatConnect HMAC Authorization"""

    def __init__(self, tc_token: Callable | Sensitive | str | Token):
        """Initialize the Class properties."""
        # super().__init__()
        auth.AuthBase.__init__(self)
        self.tc_token = tc_token

    def _token_header(self):
        """Return HMAC Authorization header value."""
        _token = None
        if isinstance(self.tc_token, Token) and isinstance(
            self.tc_token.token, Sensitive  # type: ignore
        ):
            # Token Module - The token module is provided that will handle authentication.
            _token = self.tc_token.token.value  # type: ignore
        elif callable(self.tc_token):
            # Callable - A callable method is provided that will return the token as a plain
            #     string. The callable will have to handle token renewal.
            _token = self.tc_token()
        elif isinstance(self.tc_token, Sensitive):
            # Sensitive - A sensitive string type was passed. Likely no support for renewal.
            _token = self.tc_token.value  # type: ignore
        else:
            # String - A string type was passed. Likely no support for renewal.
            _token = self.tc_token

        # Return formatted token
        return f'TC-Token {_token}'

    def __call__(self, r: Request) -> Request:
        """Add the authorization headers to the request."""
        timestamp = int(time.time())

        # Add required headers to auth.
        r.headers['Authorization'] = self._token_header()
        r.headers['Timestamp'] = timestamp
        return r
