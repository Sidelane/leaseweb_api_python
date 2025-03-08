from .config import BASE_URL
from .helper import make_http_get_request, camel_to_snake, nested_camel_to_snake
from .auth_provider import LeasewebAuthenticationProvider
from .types.error import APIError
from .types.dedicated_server import DedicatedServer
from .types.metrics import MetricValues
from .types.network import Ip4, Nullroute, OperationNetworkInterface
from .types.notification import NotificationSetting, DataTrafficNotificationSetting
from .types.hardware import HardwareInformation
from .types.parameters import (
    QueryParameters,
    NetworkTypeParameter,
    ShowMetricsParameter,
)
from .types.credentials import Credential, CredentialWithoutPassword, CredentialType


class DedicatedServices:

    def __init__(self, auth: LeasewebAuthenticationProvider):
        self._auth = auth

    # List servers
    def list_servers(
        self, query_parameters: dict[str, int | str] = None
    ) -> list[DedicatedServer] | APIError:
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
            case 200:
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
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case 200:
                server = {
                    camel_to_snake(k): nested_camel_to_snake(v) for k, v in data.items()
                }
                return DedicatedServer.model_validate(server)
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
            case 200:
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
            case 200:
                ip = {
                    camel_to_snake(k): nested_camel_to_snake(v) for k, v in data.items()
                }
                return Ip4.model_validate(ip)
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
                return data
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
            case 200:
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
    def get_server_credentials(self, server_id: str, credential_type: CredentialType, username: str) -> dict[str, str] | APIError:
        r = make_http_get_request(
            "GET",
            f"{BASE_URL}/bareMetals/v2/servers/{server_id}/credentials/{credential_type.value}/{username}",
            self._auth.get_auth_header(),
        )
        data = r.json()

        match r.status_code:
            case 200:
                return Credential.model_validate(data)
            case _:
                converted_data = {camel_to_snake(k): v for k, v in data.items()}
                if "error_code" not in converted_data:
                    converted_data["error_code"] = str(r.status_code)
                return APIError(**converted_data)
