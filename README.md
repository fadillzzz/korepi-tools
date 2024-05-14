# Korepi Tools

Some Korepi related stuff that I wrote while learning how to hack

## Prerequisites

You'll want to have at least Node 18 or newer. Don't forget to install the dependencies with `npm i`.

## How to Use (Local auth)

1. Launch Korepi once without any license, and it should give you a hardware ID.
2. Then run the `license_gen.js` which will asks you for your HWID and generates a license file to use.
3. **Copy** (don't cut) the license file into the same folder where the exe is located.
4. Run `ssl_gen.js` and install the generated certificated (`certs/md5c.korepi.com.crt`) as a trusted root certificate.
5. Set your DNS resolver to the following address:
```
49.13.228.83
```
6. Edit your hosts file and add the following line:
```
127.0.0.1 dns.quad9.net
```
7. Then start `server.js` and launch Korepi.

## How to Use (Online auth)

1. In the directory where Korepi executable is located, create a file named `license.json` and copy the following line into it:

```
{"license":"KOREPI-REAL-KEY"}
```
2. Run `ssl_gen.js` and install the generated certificated (`certs/md5c.korepi.com.crt`) as a trusted root certificate.
3. Edit your hosts file and add the following lines:
```
127.0.0.1 auth.Btxo.cn
```
4. Then start `server.js` and launch Korepi.

**NOTE:** For future launches, you only need to run the `server.js` file (no need to regenerate the license or SSL).

## Credits

- Anonymous for providing a key for testing
- [notmarek](https://github.com/notmarek) for his help in finding the salt for the payload signature
