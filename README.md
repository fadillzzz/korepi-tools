# Korepi Tools

Some Korepi related stuff that I wrote while learning how to hack

## Prerequisites

You'll want to have at least Node 18 or newer. Don't forget to install the dependencies with `npm i`.

Additionally, to route the requests to our local server, you'll want to install `dnscrypt-proxy` because editing the hosts file no longer works after version 1.3.0.

## How to Use (Local auth)

1. Launch Korepi once without any license, and it should give you a hardware ID.
2. Then run the `license_gen.js` which will asks you for your HWID and generates a license file to use.
3. **Copy** (don't cut) the license file into the same folder where the exe is located.
4. Run `ssl_gen.js` and install the generated certificated (`certs/md5c.korepi.com.crt`) as a trusted root certificate.
5. Create a new file called `captive-portals.txt` in the folder where you have DNSCrypt installed, and add the following lines:
```
md5c.korepi.com 127.0.0.1
md5c.mxmicah.me 127.0.0.1
```
6. Edit your DNSCrypt config (usually called `dnscrypt-proxy.toml`) and enable "Captive portal handling" by pointing the `map_file` variable to your `captive-portals.txt`:
```
[captive_portals]

## A file that contains a set of names used by operating systems to
## check for connectivity and captive portals, along with hard-coded
## IP addresses to return.

map_file = 'captive-portals.txt'
```
7. Then start `server.js` and launch Korepi.

## How to Use (Online auth)

1. In the directory where Korepi executable is located, create a file named `license.json` and copy the following line into it:

```
{"license":"KOREPI-REAL-KEY"}
```
2. Run `ssl_gen.js` and install the generated certificated (`certs/md5c.korepi.com.crt`) as a trusted root certificate.
3. Create a new file called `captive-portals.txt` in the folder where you have DNSCrypt installed, and add the following lines:
```
md5c.korepi.com 127.0.0.1
md5c.mxmicah.me 127.0.0.1
```
4. Edit your DNSCrypt config (usually called `dnscrypt-proxy.toml`) and enable "Captive portal handling" by pointing the `map_file` variable to your `captive-portals.txt`:
```
[captive_portals]

## A file that contains a set of names used by operating systems to
## check for connectivity and captive portals, along with hard-coded
## IP addresses to return.

map_file = 'captive-portals.txt'
```
5. Then start `server.js` and launch Korepi.

**NOTE:** For future launches, you only need to run the `server.js` file (no need to regenerate the license or SSL).

## Credits

- Anonymous for providing a key for testing
- [notmarerk](https://github.com/notmarek) for his help in finding the salt for the payload signature