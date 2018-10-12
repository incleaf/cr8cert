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

## Demo

![demo](https://user-images.githubusercontent.com/7221609/46851338-25a42080-ce32-11e8-8784-a12420aa968c.gif)

## Credit

- `cr8cert` is highly inspired by [mkcert](https://github.com/FiloSottile/mkcert). 
- Thanks to [@limeburst](https://github.com/limeburst) for leading me to Rust world, and [@amolorsy](https://github.com/amolorsy) for suggesting me a nice name.
