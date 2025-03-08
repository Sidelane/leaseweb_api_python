class LeasewebAuthenticationProvider:
    def __init__(self, api_token: str):
        self._api_token = api_token

    def get_token(self) -> str:
        return self._api_token

    def get_auth_header(self) -> dict[str, str]:
        return {"X-LSW-Auth": self.get_token()}
