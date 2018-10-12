# cr8cert
Create an SSL certificate for local development with zero configuration ✨

## Demo

<img src="https://user-images.githubusercontent.com/7221609/46851911-1cb44e80-ce34-11e8-85c8-7b4ce4bde1df.gif" width="600">

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

## Credit

- `cr8cert` is highly inspired by [mkcert](https://github.com/FiloSottile/mkcert). 
- Thanks to [@limeburst](https://github.com/limeburst) for leading me to Rust world, and [@amolorsy](https://github.com/amolorsy) for suggesting me a nice name.
