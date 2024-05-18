# Korepi Tools

Some Korepi related stuff that I wrote while learning how to hack

## Prerequisites

You'll want to have at least Node 18 or newer. Don't forget to install the dependencies with `npm i`.

## How to Use (Local auth)

1. Launch Korepi once without any license, and it should give you a hardware ID.
2. Then run the `license_gen.js` which will asks you for your HWID and generates a license file to use.
3. **Copy** (don't cut) the license file into the same folder where the exe is located.
4. Run `ssl_gen.js` and install the generated certificated (`certs/md5c.korepi.com.crt`) as a trusted root certificate.
5. Start `server.js`.
6. Edit your hosts file (`C:\Windows\system32\drivers\etc\hosts`) and add the following lines:
```
127.0.0.1 ghp.535888.xyz
127.0.0.1 md5c.535888.xyz
```
7. Use any DLL injector that you prefer and have it auto inject `lol.dll` (available from the [releases](https://github.com/fadillzzz/korepi-tools/releases) page or compile yourself) into Korepi's launcher.
8. Launch Korepi.
9. If everything goes well, you'll eventually be prompted to enter the file path to your `md5c.korepi.com.pub` file. Simply input the file path and the game should start (unless Korepi crashes due to instability).

## Notes
- For future launches, you *may* not need to regenerate the license or the SSL certificate.
- If you're already running a DNS resolver on port 53, then I assume you know what you're doing.
- I'm not responsible for any damages you may incur from using this. This is publicly available for educational purposes only.

## Credits

- Anonymous for providing a key for testing
- [notmarek](https://github.com/notmarek) for his help in finding the salt for the payload signature
