# Leaseweb Developer API Python Wrapper
An extended python api-wrapper for the [Leaseweb Developer API](https://developer.leaseweb.com/docs/). Supports all methods and types of responses.

## Roadmap

The first step is to fully implement the Dedicated Services API.
For now we have implemented all requests for the Dedicated Services/Dedicated Servers API
The next step is to add appropriate tests for all methods implemented.

Once all of the Dedicated Servers API is implemented, it will be decided with which category we continue.

## Installation

Via uv

``` bash
$ uv sync
$ uv build
$ pip install -e .
```

## Usage

``` python
from leaseweb_api import LeasewebAuthenticationProvider, DedicatedServices, DedicatedServers

auth = LeasewebAuthenticationProvider(api_token)

# Then u can either use the DedicatedServices Class
api = DedicatedServices(auth)
print(api.dedicated_servers.get_servers())

# or DedicatedServers directly
api = DedicatedServers(auth)
print(api.get_servers())

```


## Credits

- [Sidelane](https://github.com/Sidelane)
- [All Contributors](../../contributors)

## License

The MIT License (MIT). Please see [License File](LICENSE.md) for more information.
