const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const { Packet, UDPClient, createServer: createDnsServer } = require('dns2');
const { printHeader, printSuccess, printInfo, printError, printWarn } = require('./utils/printer.js');
const resolver = UDPClient({
    dns: '1.1.1.1'
});

const options = {
    key: fs.readFileSync('certs/md5c.korepi.com.key'),
    cert: fs.readFileSync('certs/md5c.korepi.com.crt'),
    ca: [fs.readFileSync('certs/md5c.korepi.com.crt')],
};

const privateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0SxoW83nU4qAbHXqjhalMiU62ae79Ayv/EAmVfJEeCymJIpv
tTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpxG5INKIQnVi1ZE0YPP1GKUXN4nchM
31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuPo+iKQqwzKnE27Fyi0USLK82PfwCN
0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFywREoekljDot8noMOQiBo0NgqmkLL
K2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tflr1yMFQ1eAdOJqnmM5YxCv4FsU2q
pZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxdoQIDAQABAoIBAD65522oWHd38D0W
O0lyxwU7nuNIZpev+lJV1mktppS3JveMQCWDupJekCcLfIhaLJ105eLJIod/Q6WO
1pqV/1c6PBHrV3SDUtPxzX66cBUu4HvIZi0PcNxiMN6I698Gqmvq6rcrpIlKpSxL
KCtyILgRcuy9gPZ4TvUgbn785BM1Hby1LwNLPs9fhyl6QZZq4eTgyH5iGNIoDlhf
DZkyj2WbqQ9tsVS/lFPV9B0eexfTLsEYT179vTyUEwJLgcteAu7c8asC+1XU3Mer
HbXedC0vytNoGBCo1dg4QYeSgN6DKbhhLqrQY9ibR1LZv91j5fskUIiqQf3wgANs
TilkB/ECgYEA7eLKFAXbyxs1BRV0mUcu0f1DlQJGJGZoyWMe9RMxMNwaM3PcmkAa
dWE8nmLvLoMz8+5sw7BQ0ZVxgfDVVld0MnwnsJOMlLbPj3oBz0SLbZbNFrIX6jrt
K2hcjVFn/YFssYAzGtUWB9TtOFdn38K5Pj0vfDOnSIj1ngNRC4WvaRUCgYEA4Rnq
LE6sqMQCbChJEgkSkJedJem2jwGep7Dt/GgvJEIPjfZT+RaKpkFf6qDAPMmKi3eF
1chc5SqPeJ2E7bM/3L1szytQKWTBqsVqHpyVOTe0IAAybVS4Mx3ICtjTzuKgRERY
LJUVBEgWU0xnnRJqlAXIjuTkE47dDgehTafwrV0CgYBsm2tJQvd7Pluxi38lb9NX
efq98EDX442ZzFBY8b82oHax4QbpwbSSvKcxZNfwc2RnzQYJPdlYJpOhELRF7D2X
wwlX27WGPAR9a+WhnJjPmtbdsseqX+biN45x0qXYnptiWrZ6XKjnQHZhj75T8ZIj
cUnZubd5LVZ+IuOAkDNqlQKBgH77SXiZIRlLCTrONvovmANtI79BajSd60wZqQbc
FsvTYEbrEE/RgYFsG5mV+RvRbZBjamJA1vaH3ctiwJv+pCX3zavIeT4AkqetGcIO
/rb6T2hF9CxswERFppVH36Qzf8lC7KKpruNtbvqqfUDEJM8/u/Wv9WF7FARYFYxj
EogZAoGBAMNI6WOB/u4vm5QpJVW+p33xyJJTmVTmzCFXCRsOvC0gDwBZcKGe4BIR
E7CyLasw3HG9IhZYOi/KoX+UQrcAOcRPAsJmlqiQxu2qskX81AiOkhPEBprVRhj3
VqquzXQuHpi/UwwiVoBX0Qi1/bWI1t5krlF4Me17cT6hffD0N/Qr
-----END RSA PRIVATE KEY-----`;

function signPayload(payload) {
    let restructured = [];

    const keys = Object.keys(payload);
    keys.sort();

    for (const k of keys) {
        if (payload[k] !== null) {
            restructured.push(payload[k].toString());
        }
    }

    restructured = restructured.join('');

    const sign = crypto.createSign('SHA256');
    sign.write(restructured);
    sign.end();

    return sign.sign(privateKey, 'base64');
}

function getHash(payload) {
    const hash = crypto.createHash('sha256');

    let restructured = [];

    const keys = Object.keys(payload);
    keys.sort();

    for (const k of keys) {
        if (payload[k] !== null) {
            restructured.push(payload[k].toString());
        }
    }

    restructured = restructured.join('') + 'CS[]SaCFAccddCdX]CGfAfuck u crackerCS[]CgFA';

    return hash.update(restructured).digest('hex');
}

let encKey = '';
let hwid = '';

function getHmac(requestType, payload) {
    let secret = 'aaa49c02ddae6a76e805e79e8d9bb788f3c80556b43b4a70fb3513bdc4e37454';

    if (requestType !== 'init') {
        secret = encKey + '-' + secret;
    }

    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(payload);
    return hmac.digest("hex");
}

function getFakePayloadForOnlineAuth(type) {
    let payload = {};

    if (type === 'init') {
        payload = {
            success: true,
            message: "Initialized",
            sessionid: "FAKE_SESH",
            appinfo: {
                numUsers: "N/A - Use fetchStats() function in latest example",
                numOnlineUsers: "N/A - Use fetchStats() function in latest example",
                numKeys: "N/A - Use fetchStats() function in latest example",
                version: "1.0",
                customerPanelLink: "https://keyauth.cc/panel/Strigger/Korepi/"
            },
            newSession: false,
            nonce: "12345678123456781234567812345678",
        }
    } else if (type === 'checkblacklist') {
        payload = {
            success: false,
            message: 'Client is not blacklisted'
        }
    } else if (type === 'license') {
        const now = Math.floor(Date.now() / 1000);
        payload = {
            success: true,
            message: "Logged in!",
            info: {
                username: "KOREPI-REAL-KEY",
                subscriptions: [
                    {
                        subscription: "Fans & Sponsor & Tester",
                        key: "KOREPI-REAL-KEY",
                        expiry: (Math.pow(2, 32) - 1).toString(),
                        timeleft: (Math.pow(2, 32) - 1) - now,
                        level: "25" // Pertamax?
                    }
                ],
                ip: "127.0.0.1",
                hwid,
                createdate: now.toString(),
                lastlogin: now.toString()
            },
            nonce: "12345678123456781234567812345678",
        }

    } else {
        printError("Unknown Request type", type);
    }

    return payload;
}

function dnsRequestHandler(request, send, rinfo) {
    const response = Packet.createResponseFromRequest(request);
    const [question] = request.questions;
    let { name } = question;

    if (name.includes('md5c') || name.match(/dns[\d]*\.quad9\.net/) || name.includes('535888.xyz')) {
        // Can't be bothered to figure this one out right now
        if (name.includes('.localdomain')) {
            name = name.replace('.localdomain', '');
        }

        response.answers.push({
            name,
            type: Packet.TYPE.A,
            class: Packet.CLASS.IN,
            ttl: 300,
            address: '104.21.45.239'
        });

        send(response.toBuffer());
    } else {
        resolver(name).then(resolved => {
            response.answers = resolved.answers.filter(answer => answer.address !== '104.21.45.239');
            send(response.toBuffer());
        });
    }
}

const requestListener = function (req, res) {
    printInfo(req.headers.host + req.url);

    if (req.url.indexOf('/prod-api/online/subscribe/md5verify') !== -1) {
        const license = require('./enc.json');
        const path = req.url;
        const splits = path.split('/');
        const id = splits[splits.length - 1];
        const matches = id.match(/([a-z0-9]+):(\d+)\??/i);

        const payload = {
            createBy: null,
            createTime: new Date().toISOString(),
            updateBy: "anonymousUser",
            updateTime: new Date().toISOString(),
            delFlag: 0,
            remark: "Oops!",
            id: Number(matches[2]),
            roleValue: 25, // PERTAMAX?
            cardKey: null,
            expiryTime: new Date(Math.floor((Math.pow(2, 32) - 1) / 2) * 1000).toISOString(),
            lastLoginTime: new Date().toISOString(),
            hwid: matches[1],
            fileMd5: license['Encrypted.md5'],
            resetTime: null,
            resetNum: 4,
            pauseTime: null,
            status: 0
        };

        const signature = getHash(payload);

        res.setHeader('Content-type', 'application/json');
        res.end(JSON.stringify({
            msg: "Hi there",
            code: 200,
            data: payload,
            signature,
            sign2: signPayload(payload),
        }));
    } else if (req.url.indexOf('/dns-query') !== -1) {
        let chunks = [];

        req.on('data', buffer => {
            chunks = chunks.length ? chunks.concat(buffer) : buffer;
        });

        req.on('end', () => {
            dnsRequestHandler(Packet.parse(chunks), res.end.bind(res), null);
        });
    } else if (req.url.indexOf('/1.2/') !== -1) {
        let body = '';

        req.on('data', buffer => {
            body += buffer.toString(); // convert Buffer to string
        });

        req.on('end', () => {
            const matches = body.match(/type=(.+?)\&/);
            printInfo("Request type is", matches[1]);
            const requestType = matches[1];

            if (requestType === 'init') {
                const matches = body.match(/enckey=(.+?)\&/);
                encKey = matches[1];
                printInfo("Setting enckey to", encKey);
            }

            if (requestType === 'checkblacklist') {
                const matches = body.match(/hwid=(.+?)\&/);
                hwid = matches[1];
            }

            const fakePayload = getFakePayloadForOnlineAuth(requestType);

            const fakeResponse = JSON.stringify(fakePayload);

            res.setHeader("signature", getHmac(requestType, fakeResponse));
            res.end(fakeResponse);
        });
    } else if (req.url.indexOf('/https://raw.githubusercontent.com/Korepi/korepi-online-data/main/new_data.json') !== -1) {
        const payload = {
            announcement: "4.6 os&cn",
            latest_version: "1.3.1.3",
            update_required: true,
            update_url: "https://github.com/Cotton-Buds/calculator/releases",
            updated_at: "2024-05-16 03:21",
            updated_by: "Strigger(main) & Micah(auth) & EtoShinya(tech)",
            update_diff: {
                added_features: [
                    "fix all 409",
                    "Fix camera issues"
                ],
                deleted_features: [
                    "修复所有失效功能",
                    "Restore all malfunctioning features."
                ],
                total_size: "78.0 MB"
            },
            compatible_versions: [
                "none"
            ]
        };

        res.setHeader('Content-type', 'application/json');
        res.end(JSON.stringify({
            msg: "success",
            code: 200,
            data: payload,
            sign2: signPayload({
                announcement: payload.announcement,
                latest_version: payload.latest_version,
                update_required: payload.update_required,
                update_url: payload.update_url,
                updated_at: payload.updated_at,
                updated_by: payload.updated_by,
            })
        }));
    } else {
        res.end("This may not be the page you're looking for.");
    }
};

console.clear();
printHeader();

const server = https.createServer(options, requestListener);

server.listen(443, "0.0.0.0", () => {
    printSuccess("Server started. Listening on port 443");
    printSuccess("You may now launch Korepi Launcher.");
});

const dnsServer = createDnsServer({
    udp: true,
    handle: dnsRequestHandler
});

dnsServer.on('error', (err) => {
    printError('DNS Server error');
    printError(err);
    if (err.code === 'EADDRINUSE') {
        printWarn('Port 53 is already in use. Assuming that you have your own DNS resolver configured to handle domain name lookups :)');
    }
});

dnsServer.on('listening', () => {
    printSuccess('DNS Server started. Listening on port 53. Please set your DNS to 127.0.0.1');
    printWarn('You must keep this script running if you\'re using it as your DNS resolver.');
});

dnsServer.listen({
    udp: {
        port: 53,
        address: '127.0.0.1',
        type: 'udp4'
    }
});
