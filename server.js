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

function getHash(payload) {
    const hash = crypto.createHash('sha256');

    let restructured = [];

    const order = [
        'cardKey',
        'createBy',
        'createTime',
        'delFlag',
        'expiryTime',
        'fileMd5',
        'hwid',
        'id',
        'lastLoginTime',
        'pauseTime',
        'remark',
        'resetNum',
        'resetTime',
        'roleValue',
        'status',
        'updateBy',
        'updateTime'
    ];

    for (const k of order) {
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

    if (name.includes('md5c') || name.match(/dns[\d]*\.quad9\.net/)) {
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
            signature
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
