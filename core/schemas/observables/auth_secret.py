from typing import Literal

from core.schemas import observable


class AuthSecret(observable.Observable):
    """
    An authentication secret, such as a private key, public key, or certificate.
    """

    type: Literal["auth_secret"] = "auth_secret"
    auth_type: str = ""  # can be pubkey, privkey, cert, ...
    name: str = ""  # keypair name as found in aws key pairs
