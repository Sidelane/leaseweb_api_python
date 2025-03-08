from re import sub
from requests import request, Response


def camel_to_snake(text: str) -> str:
    return sub(r"(?<!^)(?=[A-Z])", "_", text).lower()


def nested_camel_to_snake(value):
    if isinstance(value, dict):
        return {camel_to_snake(k): nested_camel_to_snake(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [nested_camel_to_snake(v) for v in value]
    return value


def make_http_request(
    method: str, url: str, headers: dict[str, str], params: dict[str, int | str] = None
) -> Response:

    if params is not None:
        unpacked = [(k, v) for k, v in params.items()]
        url += "?" + "&".join([f"{k}={v}" for k, v in unpacked])
    return request(method, url, headers=headers)
