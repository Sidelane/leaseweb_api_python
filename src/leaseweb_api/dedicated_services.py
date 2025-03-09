from requests.exceptions import JSONDecodeError

from .config import BASE_URL
from .helper import (
    make_http_get_request,
    camel_to_snake,
    nested_camel_to_snake,
    build_put_header,
)
from .auth_provider import LeasewebAuthenticationProvider
from .types.error import APIError
from .types.dedicated_server import DedicatedServer
from .types.metrics import MetricValues
from .types.network import Ip4, Nullroute, OperationNetworkInterface, IPUpdate
from .types.notification import NotificationSetting, DataTrafficNotificationSetting
from .types.hardware import HardwareInformation
from .types.parameters import (
    QueryParameters,
    NetworkTypeParameter,
    ShowMetricsParameter,
    ListJobsParameter,
)
from .types.credentials import Credential, CredentialWithoutPassword, CredentialType
from .types.jobs import Job, Lease
from .types.enums import DetectionProfile, HTTPStatusCodes


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


class DedicatedServers:

    def __init__(self, auth: LeasewebAuthenticationProvider):
        self._auth = auth

    # List servers
    def list_servers(
        self, query_parameters: dict[str, int | str] = None
    ) -> list[DedicatedServer] | APIError:
        """
    Retrieve a list of dedicated servers from the Leaseweb API.
    
    This method fetches all dedicated servers associated with the authenticated account
    and returns them as a list of DedicatedServer objects. The results can be filtered
    using query parameters.
    
    Args:
        query_parameters: Optional dictionary containing query parameters to filter results.
            Supported parameters include:
            - limit: Maximum number of servers to return
            - offset: Number of servers to skip for pagination
            - reference: Filter by server reference
            - ip: Filter by IP address
            - macAddress: Filter by MAC address
            - site: Filter by data center location
            - privateRackId: Filter by private rack ID
            - privateNetworkCapable: Filter by private network capability (bool)
            - privateNetworkEnabled: Filter by private network status (bool)
            
    Returns:
        Either a list of DedicatedServer objects when successful (HTTP 200), or an
        APIError object containing error details when the API request fails.
        
    Examples:
        # Get all servers
        servers = dedicated_servers.list_servers()
        
        # Get servers with pagination
        params = {"limit": 10, "offset": 20}
        servers = dedicated_servers.list_servers(params)
        
        # Filter by reference
        params = {"reference": "my-server-reference"}
        servers = dedicated_servers.list_servers(params)
    """
        if query_parameters is not None:
            query_parameters = {
                k: v for k, v in query_parameters.dict().items() if v is not None
            }
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers",
            self._auth.get_auth_header(),
            params=query_parameters,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for server in data["servers"]:
                    server = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in server.items()
                    }
                    ret.append(DedicatedServer.model_validate(server))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Get server
    def get_server(self, server_id: str) -> DedicatedServer | APIError:
        """
        Retrieve a specific dedicated server's details from the Leaseweb API.
        
        This method fetches detailed information about a single dedicated server
        identified by its ID.
        
        Args:
            server_id: The unique identifier of the server to retrieve.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A DedicatedServer object containing all server details when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            
        Examples:
            # Get details for a specific server
            server = dedicated_servers.get_server("12345678")
            
            # Access properties of the returned server
            if not isinstance(server, APIError):
                print(f"Server name: {server.reference}")
                print(f"Server IP: {server.ip}")
        """
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                server = {
                    camel_to_snake(k): nested_camel_to_snake(v) for k, v in data.items()
                }
                return DedicatedServer.model_validate(server)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Update server
    def set_reference(self, server_id: str, reference: str) -> APIError | None:
        """
        Update the reference of a specific dedicated server.

        This method updates the reference field of a dedicated server identified by its ID.

        Args:
            server_id: The unique identifier of the server to update.
            reference: The new reference value to set for the server.

        Returns:
            None if the update is successful (HTTP 204), or an APIError object containing
            error details if the API request fails.

        Examples:
            # Update the reference of a specific server
            result = dedicated_servers.set_reference("12345678", "new-reference")

            if result is None:
                print("Reference updated successfully.")
            else:
                print(f"Failed to update reference: {result.error_message}")
        """
        r = make_http_get_request(
            "PUT",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}",
            headers=build_put_header(self._auth.get_token()),
            params=None,
            json_data={"reference": reference},
        )
        try:
            data = r.json()
        except JSONDecodeError:
            data = None
            pass

        match r.status_code:
            case HTTPStatusCodes.NO_CONTENT:
                return None
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List IPs
    def list_ips(self, server_id: str) -> list[Ip4] | APIError:
        """
        List all IPs associated with a specific dedicated server.

        This method retrieves all IP addresses associated with a dedicated server identified by its ID.

        Args:
            server_id: The unique identifier of the server to retrieve IPs for.

        Returns:
            Either a list of Ip4 objects when successful (HTTP 200), or an APIError object containing
            error details when the API request fails.

        Examples:
            # List all IPs for a specific server
            ips = dedicated_servers.list_ips("12345678")

            if not isinstance(ips, APIError):
                for ip in ips:
                    print(f"IP: {ip.ip}")
            else:
                print(f"Failed to list IPs: {ips.error_message}")
        """
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/ips",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for ip in data["ips"]:
                    ip = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in ip.items()
                    }
                    ret.append(Ip4.model_validate(ip))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show a server IP
    def get_server_ip(self, server_id: str, ip: str) -> Ip4 | APIError:
        """
        Retrieve detailed information about a specific IP address of a dedicated server.
        
        This method fetches information about a single IP address associated with a 
        dedicated server identified by its ID.
        
        Args:
            server_id: The unique identifier of the server the IP belongs to.
                This is usually the Leaseweb reference number for the server.
            ip: The specific IP address to retrieve information about.
                Should be in standard IPv4 or IPv6 format (e.g., "192.168.1.1").
        
        Returns:
            An Ip4 object containing details about the IP address when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            
        Examples:
            # Get details for a specific IP address
            ip_info = dedicated_servers.get_server_ip("12345678", "192.168.1.1")
            
            # Access properties of the returned IP object
            if not isinstance(ip_info, APIError):
                print(f"IP: {ip_info.ip}")
                print(f"Gateway: {ip_info.gateway}")
                print(f"Null routed: {ip_info.null_routed}")
            else:
                print(f"Failed to get IP info: {ip_info.error_message}")
        """
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/ips/{ip}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ip = {
                    camel_to_snake(k): nested_camel_to_snake(v) for k, v in data.items()
                }
                return Ip4.model_validate(ip)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Update an IP
    def update_server_ip(
        self,
        server_id: str,
        ip: str,
        detection_profile: DetectionProfile = None,
        reverse_lookup: str = None,
    ) -> IPUpdate | APIError:
        """
        Update configuration settings for a specific IP address of a dedicated server.
        
        This method allows modifying IP-specific settings such as DDoS detection profile
        and reverse DNS lookup (PTR record) for a specific IP address.
        
        Args:
            server_id: The unique identifier of the server the IP belongs to.
                This is usually the Leaseweb reference number for the server.
            ip: The specific IP address to update.
                Should be in standard IPv4 or IPv6 format (e.g., "192.168.1.1").
            detection_profile: Optional DDoS detection profile to apply to this IP.
                Must be a value from the DetectionProfile enum (e.g., DetectionProfile.ADVANCED_DEFAULT).
            reverse_lookup: Optional reverse DNS lookup value (PTR record) to set for this IP.
                This defines the hostname that will be returned when this IP is looked up via rDNS.
        
        Returns:
            An IPUpdate object containing details about the updated IP address when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            
        Examples:
            # Update the DDoS detection profile for an IP
            result = dedicated_servers.update_server_ip(
                "12345678", 
                "192.168.1.1", 
                detection_profile=DetectionProfile.ADVANCED_DEFAULT
            )
            
            # Update the reverse lookup (PTR record) for an IP
            result = dedicated_servers.update_server_ip(
                "12345678", 
                "192.168.1.1", 
                reverse_lookup="server1.example.com"
            )
            
            # Update both settings at once
            result = dedicated_servers.update_server_ip(
                "12345678", 
                "192.168.1.1", 
                detection_profile=DetectionProfile.ADVANCED_DEFAULT,
                reverse_lookup="server1.example.com"
            )
        """
        body = {}
        if detection_profile is not None:
            body["detectionProfile"] = detection_profile.value
        if reverse_lookup is not None:
            body["reverseLookup"] = reverse_lookup

        r = make_http_get_request(
            "PUT",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/ips/{ip}",
            headers=build_put_header(self._auth.get_token()),
            params=None,
            json_data=body,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return IPUpdate.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Null route an IP
    def nullroute_ip(self, server_id: str, ip: str) -> APIError | None:
        """
        Apply null-routing to a specific IP address to mitigate DDoS attacks.
        
        This method instructs the network to drop all traffic to and from the specified IP address,
        which is useful for mitigating DDoS attacks by isolating the targeted IP.
        
        Args:
            server_id: The unique identifier of the server the IP belongs to.
                This is usually the Leaseweb reference number for the server.
            ip: The specific IP address to null-route.
                Should be in standard IPv4 or IPv6 format (e.g., "192.168.1.1").
        
        Returns:
            An IPUpdate object containing details about the update when successful (HTTP 202 Accepted),
            or an APIError object containing error details when the API request fails.
                
        Examples:
            # Null-route an IP address that's under attack
            result = dedicated_servers.nullroute_ip("12345678", "192.168.1.1")
            
            # Check if the null-routing was successful
            if not isinstance(result, APIError):
                print("IP has been successfully null-routed")
            else:
                print(f"Failed to null-route IP: {result.error_message}")
        """
        r = make_http_get_request(
            "POST",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/ips/{ip}/null",
            headers=build_put_header(self._auth.get_token()),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.ACCEPTED:
                return IPUpdate.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Un-null route an IP
    def un_nullroute_ip(self, server_id: str, ip: str) -> APIError | None:
        """
        Remove null-routing from a previously null-routed IP address.
        
        This method restores normal network traffic to and from the specified IP address
        after it was previously null-routed, typically when a DDoS attack has subsided.
        
        Args:
            server_id: The unique identifier of the server the IP belongs to.
                This is usually the Leaseweb reference number for the server.
            ip: The specific IP address to remove null-routing from.
                Should be in standard IPv4 or IPv6 format (e.g., "192.168.1.1").
        
        Returns:
            An IPUpdate object containing details about the update when successful (HTTP 202 Accepted),
            or an APIError object containing error details when the API request fails.
                
        Examples:
            # Remove null-routing from a previously null-routed IP
            result = dedicated_servers.un_nullroute_ip("12345678", "192.168.1.1")
            
            # Check if the removal of null-routing was successful
            if not isinstance(result, APIError):
                print("IP has been successfully un-null-routed")
            else:
                print(f"Failed to remove null-routing: {result.error_message}")
        """
        r = make_http_get_request(
            "POST",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/ips/{ip}/unnull",
            headers=build_put_header(self._auth.get_token()),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.ACCEPTED:
                return IPUpdate.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show null route history
    def get_nullroute_history(
        self, server_id: str, query_parameters: QueryParameters = None
    ) -> list[Nullroute]:
        """
        Retrieve the null-routing history for a specific dedicated server.
        
        This method fetches a list of past null-routing events for a dedicated server,
        including when the null-routing was applied, any comments, and when it was removed.
        
        Args:
            server_id: The unique identifier of the server to retrieve null-route history for.
                This is usually the Leaseweb reference number for the server.
            query_parameters: Optional QueryParameters object containing pagination parameters.
                - limit: Maximum number of history entries to return
                - offset: Number of entries to skip for pagination
                
        Returns:
            A list of Nullroute objects containing details about past null-routing events when 
            successful (HTTP 200), or an APIError object containing error details when the API 
            request fails.
                
        Examples:
            # Get all null-routing history for a server
            history = dedicated_servers.get_nullroute_history("12345678")
            
            # Get null-routing history with pagination
            params = QueryParameters(limit=10, offset=0)
            history = dedicated_servers.get_nullroute_history("12345678", params)
            
            # Process the null-routing history
            if not isinstance(history, APIError):
                for entry in history:
                    print(f"IP nulled at: {entry.nulled_at}")
                    print(f"Reason: {entry.comment}")
                    if entry.automated_unnulling_at:
                        print(f"Auto-removal scheduled for: {entry.automated_unnulling_at}")
            else:
                print(f"Failed to get null-routing history: {history.error_message}")
        """
        if query_parameters is not None:
            query_parameters = {
                k: v for k, v in query_parameters.dict().items() if v is not None
            }
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/nullRouteHistory",
            self._auth.get_auth_header(),
            params=query_parameters,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for nullroute in data["nullRoutes"]:
                    nullroute = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in nullroute.items()
                    }
                    ret.append(Nullroute.model_validate(nullroute))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Delete a server from a private network
    # TODO: Test this method. I think this is working, but I dont have a server to test it.
    def remove_server_from_private_network(
        self, server_id: str, private_network_id: str
    ) -> APIError | None:
        """
        Remove a server from a private network.
        
        This method disconnects a dedicated server from a specified private network,
        removing it from the network's configuration.
        
        Args:
            server_id: The unique identifier of the server to remove from the private network.
                This is usually the Leaseweb reference number for the server.
            private_network_id: The unique identifier of the private network to remove the server from.
                
        Returns:
            None when successful (HTTP 202 Accepted), or an APIError object 
            containing error details when the API request fails.
                
        Examples:
            # Remove a server from a private network
            result = dedicated_servers.remove_server_from_private_network(
                "12345678", 
                "pn-12345"
            )
            
            # Check if the removal was successful
            if result is None:
                print("Server successfully removed from private network")
            else:
                print(f"Failed to remove server from private network: {result.error_message}")
                
        Notes:
            This method has not been thoroughly tested, as noted in the implementation.
        """
        r = make_http_get_request(
            "DELETE",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/privateNetworks/{private_network_id}",
            self._auth.get_auth_header(),
        )

        try:
            data = r.json()
        except JSONDecodeError:
            data = None
            pass

        match r.status_code:
            case HTTPStatusCodes.ACCEPTED:
                return None
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Add a server to private network
    # TODO: Test this method. I think this is working, but I dont have a server to test it.
    def add_server_to_private_network(
        self, server_id: str, private_network_id: str, link_speed: int
    ) -> APIError | None:
        """
        Add a dedicated server to a private network.
        
        This method connects a dedicated server to a specified private network with
        a given link speed, enabling private communication between servers in the network.
        
        Args:
            server_id: The unique identifier of the server to add to the private network.
                This is usually the Leaseweb reference number for the server.
            private_network_id: The unique identifier of the private network to add the server to.
            link_speed: The speed of the network connection in Mbps.
                Common values are 100, 1000 (1Gbps), or 10000 (10Gbps).
                
        Returns:
            None when successful (HTTP 204 No Content), or an APIError object 
            containing error details when the API request fails.
                
        Examples:
            # Add a server to a private network with a 1Gbps link
            result = dedicated_servers.add_server_to_private_network(
                "12345678", 
                "pn-12345",
                1000
            )
            
            # Check if the addition was successful
            if result is None:
                print("Server successfully added to private network")
            else:
                print(f"Failed to add server to private network: {result.error_message}")
                
        Notes:
            This method has not been thoroughly tested, as noted in the implementation.
        """
        r = make_http_get_request(
            "PUT",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/privateNetworks/{private_network_id}",
            self._auth.get_auth_header(),
            json_data={"linkSpeed": link_speed},
        )

        try:
            data = r.json()
        except JSONDecodeError:
            data = None
            pass

        match r.status_code:
            case HTTPStatusCodes.NO_CONTENT:
                return None
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List network interfaces
    def get_network_interfaces(
        self, server_id: str
    ) -> list[OperationNetworkInterface] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/networkInterfaces",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for interface in data["networkInterfaces"]:
                    interface = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in interface.items()
                    }
                    ret.append(OperationNetworkInterface.model_validate(interface))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Close all network interfaces
    def close_all_network_interfaces(self, server_id: str) -> APIError | None:
        r = make_http_get_request(
            "POST",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/networkInterfaces/close",
            self._auth.get_auth_header(),
        )

        try:
            data = r.json()
        except JSONDecodeError:
            data = None
            pass

        match r.status_code:
            case HTTPStatusCodes.NO_CONTENT:
                return None
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Open all network interfaces
    def open_all_network_interfaces(self, server_id: str) -> APIError | None:
        r = make_http_get_request(
            "POST",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/networkInterfaces/open",
            self._auth.get_auth_header(),
        )

        try:
            data = r.json()
        except JSONDecodeError:
            data = None
            pass

        match r.status_code:
            case HTTPStatusCodes.NO_CONTENT:
                return None
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show a network interface
    def get_network_interface(
        self, server_id: str, network_type: NetworkTypeParameter
    ) -> OperationNetworkInterface | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/networkInterfaces/{network_type.value}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                interface = {
                    camel_to_snake(k): nested_camel_to_snake(v) for k, v in data.items()
                }
                return OperationNetworkInterface.model_validate(interface)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Inspect DDoS notification settings
    def get_ddos_notification_settings(
        self, server_id: str
    ) -> dict[str, str] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/notificationSettings/ddos",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Update DDoS notification settings
    def update_ddos_notification_settings(
        self, server_id: str, nulling: bool, scrubbing: bool) -> APIError | None:

        nulling = "ENABLED" if nulling else "DISABLED"
        scrubbing = "ENABLED" if scrubbing else "DISABLED"

        r = make_http_get_request(
            "PUT",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/notificationSettings/ddos",
            headers=build_put_header(self._auth.get_token()),
            json_data={"nulling": nulling, "scrubbing": scrubbing},
        )

        try:
            data = r.json()
        except JSONDecodeError:
            data = None
            pass

        match r.status_code:
            case HTTPStatusCodes.NO_CONTENT:
                return None
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show bandwidth metrics
    def get_bandwidth_metrics(
        self, server_id: str, query_parameters: ShowMetricsParameter
    ) -> MetricValues | APIError:

        if query_parameters is not None:
            query_parameters = {
                k: v for k, v in query_parameters.dict().items() if v is not None
            }
            query_parameters["from"] = query_parameters["start"]
            query_parameters.pop("start")
            query_parameters["from"] = query_parameters["from"].isoformat() + "Z"
            query_parameters["to"] = query_parameters["to"].isoformat() + "Z"
            query_parameters["aggregation"] = query_parameters["aggregation"].value

        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/metrics/bandwidth",
            self._auth.get_auth_header(),
            params=query_parameters,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return MetricValues.model_validate(data["metrics"])
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show datatraffic metrics
    def get_datatraffic_metrics(
        self, server_id: str, query_parameters: ShowMetricsParameter
    ) -> MetricValues | APIError:

        if query_parameters is not None:
            query_parameters = {
                k: v for k, v in query_parameters.dict().items() if v is not None
            }
            query_parameters["from"] = query_parameters["start"]
            query_parameters.pop("start")
            query_parameters["from"] = query_parameters["from"].isoformat() + "Z"
            query_parameters["to"] = query_parameters["to"].isoformat() + "Z"
            query_parameters["aggregation"] = query_parameters["aggregation"].value

        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/metrics/datatraffic",
            self._auth.get_auth_header(),
            params=query_parameters,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return MetricValues.model_validate(data["metrics"])
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List bandwidth notification settings
    def get_bandwidth_notification_settings(
        self, server_id: str
    ) -> dict[str, str] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/notificationSettings/bandwidth",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show a bandwidth notification setting
    def get_bandwidth_notification_setting(
        self, server_id: str, notification_setting_id: str
    ) -> NotificationSetting | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/notificationSettings/bandwidth/{notification_setting_id}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return NotificationSetting.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List data traffic notification settings
    def get_bandwidth_notification_setting(
        self, server_id: str
    ) -> DataTrafficNotificationSetting | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/notificationSettings/datatraffic",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return DataTrafficNotificationSetting.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show a datatraffic notification setting
    def get_datatraffic_notification_setting(
        self, server_id: str, notification_setting_id: str
    ) -> DataTrafficNotificationSetting | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/notificationSettings/datatraffic/{notification_setting_id}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return DataTrafficNotificationSetting.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show hardware information
    def get_hardware_information(
        self, server_id: str
    ) -> HardwareInformation | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/hardwareInfo",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                print(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List control panels
    def get_control_panels(self) -> list[dict[str, str]] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/controlPanels",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data["controlPanels"]
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List operating systems
    def get_operating_systems(
        self, control_panel_id: str = None
    ) -> list[dict[str, str]] | APIError:
        if control_panel_id is not None:
            control_panel_id = {"controlPanelId": control_panel_id}
            control_panel_id = {
                k: v for k, v in control_panel_id.items() if v is not None
            }
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/operatingSystems",
            self._auth.get_auth_header(),
            params=control_panel_id,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data["operatingSystems"]
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show operating system
    def get_operating_system(
        self, operating_system_id: str
    ) -> dict[str, str] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/operatingSystems/{operating_system_id}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Recue Images
    def get_rescue_images(self) -> list[dict[str, str]] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/rescueImages",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data["rescueImages"]
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List server credentials
    def get_server_credentials_without_password(
        self, server_id: str
    ) -> CredentialWithoutPassword | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/credentials",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for cred in data["credentials"]:
                    cred = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in cred.items()
                    }
                    ret.append(CredentialWithoutPassword.model_validate(cred))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List server credentials by type
    def get_server_credentials_by_type_without_password(
        self, server_id: str, credential_type: CredentialType
    ) -> list[dict[str, str]] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/credentials/{credential_type.value}",
            self._auth.get_auth_header(),
        )
        data = r.json()
        print(data)

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for cred in data["credentials"]:
                    cred = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in cred.items()
                    }
                    ret.append(CredentialWithoutPassword.model_validate(cred))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show server credentials
    def get_server_credentials(
        self, server_id: str, credential_type: CredentialType, username: str
    ) -> dict[str, str] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/credentials/{credential_type.value}/{username}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return Credential.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List jobs
    def get_jobs(
        self, server_id: str, query_parameter: ListJobsParameter = None
    ) -> list[Job] | APIError:
        if query_parameter is not None:
            query_parameter = {
                k: v for k, v in query_parameter.dict().items() if v is not None
            }

        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/jobs",
            self._auth.get_auth_header(),
            params=query_parameter,
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for job in data["jobs"]:
                    job = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in job.items()
                    }
                    ret.append(Job.model_validate(job))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show a job
    def get_job(self, server_id: str, job_id: str) -> Job | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/jobs/{job_id}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                job = {
                    camel_to_snake(k): nested_camel_to_snake(v) for k, v in data.items()
                }
                return Job.model_validate(job)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List DHCP reservations
    def get_dhcp_reservations(self, server_id: str) -> Lease | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/leases",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                ret = []
                for lease in data["leases"]:
                    lease = {
                        camel_to_snake(k): nested_camel_to_snake(v)
                        for k, v in lease.items()
                    }
                    ret.append(Lease.model_validate(lease))
                return ret
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # Show power status
    def get_power_status(self, server_id: str) -> dict[str, str] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/powerInfo",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return data
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)
