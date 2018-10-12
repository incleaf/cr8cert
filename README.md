# cr8cert
Create an SSL certificate for local development with zero configuration ✨

## Installation

```sh
$ brew tap incleaf/homebrew-cli
$ brew install cr8cert
```

## Usage

### `cr8cert --install`

Install the local CA in the system trust store.

### `cr8cert --create [hostname,]`

Create a certificate with the given host names.

```sh
$ mkcert --create 127.0.0.1 hyeonsulee.com
```

### `cr8cert --uninstall`

Uninstall the local CA in the system trust store.
