class LeasewebAuthenticationProvider:
    """
    Authentication provider for the Leaseweb API.
    
    This class manages authentication with the Leaseweb API using an API token.
    It handles storing the token securely and generating the appropriate authorization
    headers for API requests.
    
    Attributes:
        _api_token: The private API token used for authentication.
    
    Examples:
        # Create an authentication provider with your API token
        auth = LeasewebAuthenticationProvider("YOUR_API_TOKEN_HERE")
        
        # Use with other API classes
        dedicated_services = DedicatedServices(auth)
        
        # Get authentication headers for manual requests
        headers = auth.get_auth_header()
    """
    
    def __init__(self, api_token: str):
        """
        Initialize the authentication provider with an API token.
        
        Args:
            api_token: The Leaseweb API token for authentication.
                This can be generated from the Leaseweb customer portal.
        """
        self._api_token = api_token

    def get_token(self) -> str:
        """
        Get the stored API token.
        
        Returns:
            The API token string.
        """
        return self._api_token

    def get_auth_header(self) -> dict[str, str]:
        """
        Get authentication headers required for Leaseweb API requests.
        
        Returns:
            A dictionary containing the X-LSW-Auth header with the API token.
        """
        return {"X-LSW-Auth": self.get_token()}