from .auth_provider import LeasewebAuthenticationProvider
from .dedicated_servers import DedicatedServers


class DedicatedServices:
    """
    A class to interact with Leaseweb's dedicated services API.

    This class provides methods to manage and retrieve information about dedicated servers,
    including listing servers, getting server details, updating server references, managing IPs,
    handling network interfaces, and more.

    Attributes:
        auth (LeasewebAuthenticationProvider): The authentication provider for Leaseweb API.

    Methods:
        TODO: Add Methods
    """

    def __init__(self, auth: LeasewebAuthenticationProvider):
        self._auth = auth
        self.dedicated_servers = DedicatedServers(auth)
