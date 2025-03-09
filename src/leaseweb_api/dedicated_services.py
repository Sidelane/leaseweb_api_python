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
