from .config import BASE_URL
from .helper import make_http_request, camel_to_snake, nested_camel_to_snake
from .auth_provider import LeasewebAuthenticationProvider
from .types.error import APIError
from .types.dedicated_server import DedicatedServer


class DedicatedServers:

    def __init__(self, auth: LeasewebAuthenticationProvider):
        self._auth = auth

    def list_servers(
        self, query_parameters: dict[str, int | str] = None
    ) -> list[DedicatedServer] | APIError:
        if query_parameters is not None:
            query_parameters = {
                k: v for k, v in query_parameters.dict().items() if v is not None
            }
        r = make_http_request(
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

    def get_server(self, server_id: str) -> DedicatedServer | APIError:
        r = make_http_request(
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
