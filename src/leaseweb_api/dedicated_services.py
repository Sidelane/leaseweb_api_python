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
        """
        Retrieve a list of network interfaces for a specific dedicated server.
        
        This method fetches information about all network interfaces associated with a 
        dedicated server, including status, link speed, and connection details.
        
        Args:
            server_id: The unique identifier of the server to retrieve network interfaces for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A list of OperationNetworkInterface objects containing network interface details 
            when successful (HTTP 200), or an APIError object containing error details 
            when the API request fails.
                
        Examples:
            # Get all network interfaces for a server
            interfaces = dedicated_servers.get_network_interfaces("12345678")
            
            # Process the network interfaces
            if not isinstance(interfaces, APIError):
                for interface in interfaces:
                    print(f"Interface type: {interface.type}")
                    print(f"Link speed: {interface.link_speed}")
                    print(f"Status: {interface.status}")
            else:
                print(f"Failed to get network interfaces: {interfaces.error_message}")
        """
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
        """
        Close all network interfaces on a specific dedicated server.
        
        This method administratively shuts down all network interfaces on a dedicated server,
        effectively disconnecting it from all networks. This can be useful for security purposes
        or when preparing a server for maintenance.
        
        Args:
            server_id: The unique identifier of the server to close network interfaces for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            None when successful (HTTP 204 No Content), or an APIError object containing 
            error details when the API request fails.
                
        Examples:
            # Close all network interfaces on a server
            result = dedicated_servers.close_all_network_interfaces("12345678")
            
            # Check if the operation was successful
            if result is None:
                print("All network interfaces closed successfully")
            else:
                print(f"Failed to close network interfaces: {result.error_message}")
                
        Warning:
            This action will disconnect the server from all networks, including the internet.
            Ensure you have an alternative way to access the server (like IPMI/KVM) before
            executing this method.
        """
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
        """
        Open all network interfaces on a specific dedicated server.
        
        This method administratively enables all network interfaces on a dedicated server,
        reconnecting it to all configured networks. This is typically used after interfaces
        have been closed, for example after maintenance or security measures.
        
        Args:
            server_id: The unique identifier of the server to open network interfaces for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            None when successful (HTTP 204 No Content), or an APIError object containing 
            error details when the API request fails.
                
        Examples:
            # Open all network interfaces on a server
            result = dedicated_servers.open_all_network_interfaces("12345678")
            
            # Check if the operation was successful
            if result is None:
                print("All network interfaces opened successfully")
            else:
                print(f"Failed to open network interfaces: {result.error_message}")
        """
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
        """
        Retrieve detailed information about a specific network interface type on a dedicated server.
        
        This method fetches detailed information about a single network interface (public, 
        internal, or remote management) on a dedicated server identified by its ID.
        
        Args:
            server_id: The unique identifier of the server to retrieve the network interface for.
                This is usually the Leaseweb reference number for the server.
            network_type: The type of network interface to retrieve.
                Must be a value from the NetworkTypeParameter enum (e.g., NetworkTypeParameter.PUBLIC,
                NetworkTypeParameter.INTERNAL, or NetworkTypeParameter.REMOTE_MANAGEMENT).
        
        Returns:
            An OperationNetworkInterface object containing details about the network interface
            when successful (HTTP 200), or an APIError object containing error details when 
            the API request fails.
                
        Examples:
            # Get the public network interface for a server
            interface = dedicated_servers.get_network_interface(
                "12345678", 
                NetworkTypeParameter.PUBLIC
            )
            
            # Access properties of the returned network interface
            if not isinstance(interface, APIError):
                print(f"Link speed: {interface.link_speed}")
                print(f"Status: {interface.status}")
                print(f"Switch interface: {interface.switch_interface}")
            else:
                print(f"Failed to get network interface: {interface.error_message}")
        """
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
        """
        Retrieve DDoS notification settings for a specific dedicated server.
        
        This method fetches the current DDoS notification settings configured for a dedicated server,
        including whether nulling and scrubbing notifications are enabled or disabled.
        
        Args:
            server_id: The unique identifier of the server to retrieve DDoS notification settings for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A dictionary containing DDoS notification settings when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The dictionary typically contains keys like 'nulling' and 'scrubbing' with 
            values of 'ENABLED' or 'DISABLED'.
                
        Examples:
            # Get DDoS notification settings for a server
            settings = dedicated_servers.get_ddos_notification_settings("12345678")
            
            # Process the notification settings
            if not isinstance(settings, APIError):
                print(f"Nulling notifications: {settings.get('nulling')}")
                print(f"Scrubbing notifications: {settings.get('scrubbing')}")
            else:
                print(f"Failed to get DDoS notification settings: {settings.error_message}")
        """
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
        """
        Update DDoS notification settings for a specific dedicated server.
        
        This method configures whether the server should send notifications for DDoS-related
        events such as nulling (null-routing) and scrubbing (DDoS mitigation) actions.
        
        Args:
            server_id: The unique identifier of the server to update DDoS notification settings for.
                This is usually the Leaseweb reference number for the server.
            nulling: Whether to enable (True) or disable (False) notifications for null-routing events.
                When enabled, notifications will be sent when the server's IP addresses are null-routed.
            scrubbing: Whether to enable (True) or disable (False) notifications for DDoS scrubbing events.
                When enabled, notifications will be sent when DDoS mitigation is applied.
        
        Returns:
            None when successful (HTTP 204 No Content), or an APIError object containing 
            error details when the API request fails.
                
        Examples:
            # Enable both nulling and scrubbing notifications
            result = dedicated_servers.update_ddos_notification_settings(
                "12345678", 
                nulling=True, 
                scrubbing=True
            )
            
            # Disable nulling notifications but keep scrubbing notifications
            result = dedicated_servers.update_ddos_notification_settings(
                "12345678", 
                nulling=False, 
                scrubbing=True
            )
            
            # Check if the update was successful
            if result is None:
                print("DDoS notification settings updated successfully")
            else:
                print(f"Failed to update notification settings: {result.error_message}")
        """
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
        """
        Retrieve bandwidth usage metrics for a specific dedicated server.
        
        This method fetches bandwidth usage data (upload and download) for a dedicated server
        over a specified time period, with options for different time granularities and
        aggregation methods.
        
        Args:
            server_id: The unique identifier of the server to retrieve bandwidth metrics for.
                This is usually the Leaseweb reference number for the server.
            query_parameters: A ShowMetricsParameter object containing parameters to customize the metrics:
                - start: The start datetime for the metrics period (required)
                - to: The end datetime for the metrics period (required)
                - granularity: The time interval between data points (e.g., HOUR, DAY, WEEK)
                - aggregation: The method used to aggregate data (e.g., AVG, SUM, PERC_95)
        
        Returns:
            A MetricValues object containing bandwidth metrics data when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The MetricValues object typically contains UP_PUBLIC and DOWN_PUBLIC metrics.
                
        Examples:
            # Get bandwidth metrics for the last 24 hours with hourly granularity
            from datetime import datetime, timedelta
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=1)
            
            params = ShowMetricsParameter(
                start=start_time,
                to=end_time,
                granularity=Granularity.HOUR,
                aggregation=Aggregation.AVG
            )
            
            metrics = dedicated_servers.get_bandwidth_metrics("12345678", params)
            
            # Access the bandwidth metrics
            if not isinstance(metrics, APIError):
                if metrics.UP_PUBLIC:
                    for value in metrics.UP_PUBLIC.values:
                        print(f"Upload at {value.timestamp}: {value.value} {metrics.UP_PUBLIC.unit}")
            else:
                print(f"Failed to get bandwidth metrics: {metrics.error_message}")
        """
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
        """
        Retrieve data traffic metrics for a specific dedicated server.
        
        This method fetches data traffic consumption for a dedicated server over a specified time period,
        with options for different time granularities and aggregation methods. This helps track
        how much data has been consumed against your data traffic quota.
        
        Args:
            server_id: The unique identifier of the server to retrieve data traffic metrics for.
                This is usually the Leaseweb reference number for the server.
            query_parameters: A ShowMetricsParameter object containing parameters to customize the metrics:
                - start: The start datetime for the metrics period (required)
                - to: The end datetime for the metrics period (required)
                - granularity: The time interval between data points (e.g., HOUR, DAY, WEEK)
                - aggregation: The method used to aggregate data (e.g., AVG, SUM, PERC_95)
        
        Returns:
            A MetricValues object containing data traffic metrics when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The MetricValues object typically contains DATATRAFFIC_PUBLIC metrics.
                
        Examples:
            # Get data traffic metrics for the last 30 days with daily granularity
            from datetime import datetime, timedelta
            
            end_time = datetime.now()
            start_time = end_time - timedelta(days=30)
            
            params = ShowMetricsParameter(
                start=start_time,
                to=end_time,
                granularity=Granularity.DAY,
                aggregation=Aggregation.SUM
            )
            
            metrics = dedicated_servers.get_datatraffic_metrics("12345678", params)
            
            # Access the data traffic metrics
            if not isinstance(metrics, APIError):
                if metrics.DATATRAFFIC_PUBLIC:
                    for value in metrics.DATATRAFFIC_PUBLIC.values:
                        print(f"Data used on {value.timestamp}: {value.value} {metrics.DATATRAFFIC_PUBLIC.unit}")
            else:
                print(f"Failed to get data traffic metrics: {metrics.error_message}")
        """
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
        """
        Retrieve bandwidth notification settings for a specific dedicated server.
        
        This method fetches the current bandwidth notification settings configured for a 
        dedicated server, which determine when alerts are triggered based on bandwidth usage.
        
        Args:
            server_id: The unique identifier of the server to retrieve bandwidth notification settings for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A dictionary containing bandwidth notification settings when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The dictionary typically contains setting IDs and their configuration details.
                
        Examples:
            # Get bandwidth notification settings for a server
            settings = dedicated_servers.get_bandwidth_notification_settings("12345678")
            
            # Process the bandwidth notification settings
            if not isinstance(settings, APIError):
                for setting_id, details in settings.items():
                    print(f"Setting ID: {setting_id}")
                    print(f"Details: {details}")
            else:
                print(f"Failed to get bandwidth notification settings: {settings.error_message}")
        """
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
        """
        Retrieve detailed information about a specific bandwidth notification setting.
        
        This method fetches the configuration details of a single bandwidth notification setting
        for a dedicated server, identified by both the server ID and the notification setting ID.
        
        Args:
            server_id: The unique identifier of the server the notification setting belongs to.
                This is usually the Leaseweb reference number for the server.
            notification_setting_id: The unique identifier of the specific notification setting to retrieve.
        
        Returns:
            A NotificationSetting object containing details about the notification configuration
            when successful (HTTP 200), or an APIError object containing error details when the 
            API request fails.
                
        Examples:
            # Get a specific bandwidth notification setting
            setting = dedicated_servers.get_bandwidth_notification_setting("12345678", "bw-setting-123")
            
            # Access properties of the returned notification setting
            if not isinstance(setting, APIError):
                print(f"Threshold: {setting.threshold}")
                print(f"Unit: {setting.unit}")
                print(f"Frequency: {setting.frequency}")
            else:
                print(f"Failed to get notification setting: {setting.error_message}")
        """
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
    def get_bandwidth_notification_settings(
        self, server_id: str
    ) -> DataTrafficNotificationSetting | APIError:
        """
        Retrieve bandwidth notification settings for a specific dedicated server.
        
        This method fetches the current bandwidth notification settings configured for a 
        dedicated server, which determine when alerts are triggered based on bandwidth usage.
        
        Args:
            server_id: The unique identifier of the server to retrieve bandwidth notification settings for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A dictionary containing bandwidth notification settings when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The dictionary typically contains setting IDs and their configuration details.
                
        Examples:
            # Get bandwidth notification settings for a server
            settings = dedicated_servers.get_bandwidth_notification_settings("12345678")
            
            # Process the bandwidth notification settings
            if not isinstance(settings, APIError):
                for setting_id, details in settings.items():
                    print(f"Setting ID: {setting_id}")
                    print(f"Details: {details}")
            else:
                print(f"Failed to get bandwidth notification settings: {settings.error_message}")
        """
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
        """
        Retrieve data traffic notification settings for a specific dedicated server.
        
        This method fetches the current data traffic notification settings configured for a 
        dedicated server, which determine when alerts are triggered based on data transfer quotas.
        
        Args:
            server_id: The unique identifier of the server to retrieve data traffic notification settings for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A DataTrafficNotificationSetting object containing notification settings when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
                
        Examples:
            # Get data traffic notification settings for a server
            settings = dedicated_servers.get_datatraffic_notification_settings("12345678")
            
            # Access properties of the returned settings
            if not isinstance(settings, APIError):
                print(f"Threshold: {settings.threshold}")
                print(f"Unit: {settings.unit}")
                print(f"Frequency: {settings.frequency}")
            else:
                print(f"Failed to get data traffic notification settings: {settings.error_message}")
                
        Note:
            This method is incorrectly named in the codebase as a duplicate of get_bandwidth_notification_settings.
            It should be renamed to get_datatraffic_notification_settings to accurately reflect its purpose.
        """
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
        """
        Retrieve detailed hardware information for a specific dedicated server.
        
        This method fetches comprehensive hardware details about a dedicated server,
        including processor specifications, memory configuration, storage devices, 
        and other hardware components.
        
        Args:
            server_id: The unique identifier of the server to retrieve hardware information for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A HardwareInformation object containing detailed hardware specifications when 
            successful (HTTP 200), or an APIError object containing error details when the 
            API request fails.
                
        Examples:
            # Get hardware information for a server
            hardware_info = dedicated_servers.get_hardware_information("12345678")
            
            # Access hardware details
            if not isinstance(hardware_info, APIError):
                print(f"CPU: {hardware_info.cpu.model}")
                print(f"Memory: {hardware_info.memory.size} {hardware_info.memory.unit}")
                print(f"Disks: {len(hardware_info.disk_drives)} drives found")
            else:
                print(f"Failed to get hardware information: {hardware_info.error_message}")
        """
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/hardwareInfo",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case HTTPStatusCodes.OK:
                return HardwareInformation.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)

    # List control panels
    def get_control_panels(self) -> list[dict[str, str]] | APIError:
        """
        Retrieve a list of available control panels for dedicated servers.
        
        This method fetches all control panels that can be installed on dedicated servers,
        which is useful when provisioning or reinstalling servers with specific control panel requirements.
        
        Args:
            None
        
        Returns:
            A list of dictionaries containing control panel details when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            Each dictionary typically includes keys like 'id', 'name', and 'description'.
                
        Examples:
            # Get all available control panels
            control_panels = dedicated_servers.get_control_panels()
            
            # Process the control panels
            if not isinstance(control_panels, APIError):
                for panel in control_panels:
                    print(f"ID: {panel.get('id')}")
                    print(f"Name: {panel.get('name')}")
                    print(f"Description: {panel.get('description')}")
            else:
                print(f"Failed to get control panels: {control_panels.error_message}")
        """
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
        """
        Retrieve a list of operating systems available for installation on dedicated servers.
        
        This method fetches all operating systems that can be installed on dedicated servers,
        with optional filtering by compatibility with a specific control panel. This is useful
        when preparing for server provisioning or reinstallation.
        
        Args:
            control_panel_id: Optional ID of a control panel to filter compatible operating systems.
                When provided, only returns operating systems that are compatible with the specified
                control panel.
        
        Returns:
            A list of dictionaries containing operating system details when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            Each dictionary typically includes keys like 'id', 'name', and 'version'.
                
        Examples:
            # Get all available operating systems
            operating_systems = dedicated_servers.get_operating_systems()
            
            # Get operating systems compatible with a specific control panel
            operating_systems = dedicated_servers.get_operating_systems("CPANEL")
            
            # Process the operating systems
            if not isinstance(operating_systems, APIError):
                for os in operating_systems:
                    print(f"ID: {os.get('id')}")
                    print(f"Name: {os.get('name')}")
                    print(f"Version: {os.get('version')}")
            else:
                print(f"Failed to get operating systems: {operating_systems.error_message}")
        """
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
        """
        Retrieve detailed information about a specific operating system.
        
        This method fetches comprehensive details about a single operating system
        that is available for installation on dedicated servers, identified by its ID.
        
        Args:
            operating_system_id: The unique identifier of the operating system to retrieve.
                This ID can be obtained from the get_operating_systems method.
        
        Returns:
            A dictionary containing details about the operating system when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The dictionary typically includes keys like 'id', 'name', 'version', 'architecture',
            and 'supportedControlPanels'.
                
        Examples:
            # Get detailed information about a specific operating system
            os_info = dedicated_servers.get_operating_system("UBUNTU_20_04_64BIT")
            
            # Process the operating system details
            if not isinstance(os_info, APIError):
                print(f"Name: {os_info.get('name')}")
                print(f"Version: {os_info.get('version')}")
                print(f"Architecture: {os_info.get('architecture')}")
                print(f"Compatible control panels: {os_info.get('supportedControlPanels')}")
            else:
                print(f"Failed to get operating system info: {os_info.error_message}")
        """
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
        """
        Retrieve a list of available rescue images for dedicated servers.
        
        This method fetches all rescue images that can be used to boot a dedicated server
        in rescue mode, which is useful for troubleshooting or recovery operations when
        the main operating system is inaccessible or corrupted.
        
        Args:
            None
        
        Returns:
            A list of dictionaries containing rescue image details when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            Each dictionary typically includes keys like 'id', 'name', and 'description'.
                
        Examples:
            # Get all available rescue images
            rescue_images = dedicated_servers.get_rescue_images()
            
            # Process the rescue images
            if not isinstance(rescue_images, APIError):
                for image in rescue_images:
                    print(f"ID: {image.get('id')}")
                    print(f"Name: {image.get('name')}")
                    print(f"Description: {image.get('description')}")
            else:
                print(f"Failed to get rescue images: {rescue_images.error_message}")
        """
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
        """
        Retrieve credential information for a dedicated server without exposing passwords.
        
        This method fetches all credential records associated with a dedicated server,
        including usernames and types, but does not include the actual passwords for security reasons.
        
        Args:
            server_id: The unique identifier of the server to retrieve credentials for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A list of CredentialWithoutPassword objects containing credential information 
            when successful (HTTP 200), or an APIError object containing error details when 
            the API request fails.
                
        Examples:
            # Get all credentials for a server
            credentials = dedicated_servers.get_server_credentials_without_password("12345678")
            
            # Process the credentials
            if not isinstance(credentials, APIError):
                for cred in credentials:
                    print(f"Username: {cred.username}")
                    print(f"Type: {cred.type}")
                    print(f"Updated: {cred.last_update}")
            else:
                print(f"Failed to get credentials: {credentials.error_message}")
                
        Note:
            This method only returns credential metadata without actual passwords.
            To retrieve passwords, use the get_server_credentials method with specific credential type and username.
        """
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
        """
        Retrieve credential information of a specific type for a dedicated server without exposing passwords.
        
        This method fetches credential records associated with a dedicated server filtered by credential type,
        including usernames and types, but does not include the actual passwords for security reasons.
        
        Args:
            server_id: The unique identifier of the server to retrieve credentials for.
                This is usually the Leaseweb reference number for the server.
            credential_type: The type of credentials to retrieve.
                Must be a value from the CredentialType enum (e.g., CredentialType.OPERATING_SYSTEM, 
                CredentialType.CONTROL_PANEL).
        
        Returns:
            A list of CredentialWithoutPassword objects containing credential information 
            when successful (HTTP 200), or an APIError object containing error details when 
            the API request fails.
                
        Examples:
            # Get operating system credentials for a server
            os_credentials = dedicated_servers.get_server_credentials_by_type_without_password(
                "12345678", 
                CredentialType.OPERATING_SYSTEM
            )
            
            # Process the credentials
            if not isinstance(os_credentials, APIError):
                for cred in os_credentials:
                    print(f"Username: {cred.username}")
                    print(f"Last updated: {cred.last_update}")
            else:
                print(f"Failed to get credentials: {os_credentials.error_message}")
                
        Note:
            This method only returns credential metadata without actual passwords.
            To retrieve passwords, use the get_server_credentials method with specific credential type and username.
        """
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
        """
        Retrieve detailed credential information including passwords for a specific server account.
        
        This method fetches complete credential details including the password for a specific
        account on a dedicated server, identified by server ID, credential type, and username.
        
        Args:
            server_id: The unique identifier of the server to retrieve credentials for.
                This is usually the Leaseweb reference number for the server.
            credential_type: The type of credential to retrieve.
                Must be a value from the CredentialType enum (e.g., CredentialType.OPERATING_SYSTEM, 
                CredentialType.CONTROL_PANEL).
            username: The specific username of the credential to retrieve.
        
        Returns:
            A Credential object containing complete credential details including the password
            when successful (HTTP 200), or an APIError object containing error details when 
            the API request fails.
                
        Examples:
            # Get the root password for a server
            credentials = dedicated_servers.get_server_credentials(
                "12345678", 
                CredentialType.OPERATING_SYSTEM,
                "root"
            )
            
            # Access the returned credential details
            if not isinstance(credentials, APIError):
                print(f"Username: {credentials.username}")
                print(f"Password: {credentials.password}")
                print(f"Type: {credentials.type}")
            else:
                print(f"Failed to get credentials: {credentials.error_message}")
                
        Warning:
            This method retrieves sensitive information including passwords. Ensure that
            calls to this method are properly secured and that retrieved passwords are
            handled securely.
        """
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
        """
        Retrieve a list of jobs associated with a specific dedicated server.
        
        This method fetches the history of jobs that have been performed on a dedicated server,
        such as installations, reinstallations, rescues, or other maintenance operations.
        The results can be filtered and paginated using query parameters.
        
        Args:
            server_id: The unique identifier of the server to retrieve jobs for.
                This is usually the Leaseweb reference number for the server.
            query_parameter: Optional ListJobsParameter object containing parameters to filter results.
                Supported parameters typically include:
                - limit: Maximum number of jobs to return
                - offset: Number of jobs to skip for pagination
                - status: Filter by job status (e.g., COMPLETED, FAILED, RUNNING)
                - type: Filter by job type (e.g., RESCUE, INSTALLATION)
        
        Returns:
            A list of Job objects containing job details when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
                
        Examples:
            # Get all jobs for a server
            jobs = dedicated_servers.get_jobs("12345678")
            
            # Get jobs with pagination and filtering
            from datetime import datetime
            
            params = ListJobsParameter(
                limit=10,
                offset=0,
                status="COMPLETED"
            )
            jobs = dedicated_servers.get_jobs("12345678", params)
            
            # Process the jobs
            if not isinstance(jobs, APIError):
                for job in jobs:
                    print(f"Job ID: {job.id}")
                    print(f"Type: {job.type}")
                    print(f"Status: {job.status}")
                    print(f"Created: {job.created_at}")
            else:
                print(f"Failed to get jobs: {jobs.error_message}")
        """
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
        """
        Retrieve detailed information about a specific job associated with a dedicated server.
        
        This method fetches complete details about a single job that was performed on a
        dedicated server, identified by both the server ID and the job ID. Jobs represent
        operations like installations, reboots, rescue mode, and other maintenance actions.
        
        Args:
            server_id: The unique identifier of the server the job was performed on.
                This is usually the Leaseweb reference number for the server.
            job_id: The unique identifier of the specific job to retrieve.
                This is a UUID that can be obtained from the get_jobs method.
        
        Returns:
            A Job object containing complete details about the job when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
                
        Examples:
            # Get details for a specific job
            job = dedicated_servers.get_job("12345678", "job-uuid-12345")
            
            # Access properties of the returned job
            if not isinstance(job, APIError):
                print(f"Job type: {job.type}")
                print(f"Status: {job.status}")
                print(f"Created at: {job.created_at}")
                print(f"Running: {job.is_running}")
                
                # Access task details if available
                if job.tasks:
                    for task in job.tasks:
                        print(f"Task: {task.description}")
                        print(f"Status: {task.status}")
            else:
                print(f"Failed to get job details: {job.error_message}")
        """
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
        """
        Retrieve DHCP lease reservations for a specific dedicated server.
        
        This method fetches all DHCP lease reservations associated with a dedicated server,
        which are static IP address assignments based on MAC addresses. These are useful
        for ensuring devices always receive the same IP address when using DHCP.
        
        Args:
            server_id: The unique identifier of the server to retrieve DHCP reservations for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A list of Lease objects containing DHCP reservation details when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
                
        Examples:
            # Get all DHCP reservations for a server
            leases = dedicated_servers.get_dhcp_reservations("12345678")
            
            # Process the DHCP reservations
            if not isinstance(leases, APIError):
                for lease in leases:
                    print(f"IP Address: {lease.ip}")
                    print(f"MAC Address: {lease.mac}")
                    print(f"Hostname: {lease.hostname}")
            else:
                print(f"Failed to get DHCP reservations: {leases.error_message}")
        """
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
        """
        Retrieve the current power status of a specific dedicated server.
        
        This method fetches information about the power state of a dedicated server,
        including whether it is powered on or off, and potentially other power-related details.
        
        Args:
            server_id: The unique identifier of the server to retrieve power status for.
                This is usually the Leaseweb reference number for the server.
        
        Returns:
            A dictionary containing power status information when successful (HTTP 200),
            or an APIError object containing error details when the API request fails.
            The dictionary typically includes keys like 'status' with values such as 'ON' or 'OFF'.
                
        Examples:
            # Get the power status for a server
            power_info = dedicated_servers.get_power_status("12345678")
            
            # Process the power status
            if not isinstance(power_info, APIError):
                print(f"Power status: {power_info.get('status')}")
                # Check if the server is powered on
                if power_info.get('status') == 'ON':
                    print("Server is running")
                else:
                    print("Server is powered off")
            else:
                print(f"Failed to get power status: {power_info.error_message}")
        """
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
