const https = require('https');
const fs = require('fs');
const crypto = require('crypto');

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

    restructured = restructured.join('');

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
        console.error("Unknown request type", type);
    }

    return payload;
}

const requestListener = function (req, res) {
    console.log(new Date().toISOString() + ': ' + req.headers.host + req.url);

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
            id: matches[2],
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
    } else if (req.url.indexOf('/1.2/') !== -1) {
        let body = '';

        req.on('data', buffer => {
            body += buffer.toString(); // convert Buffer to string
        });

        req.on('end', () => {
            const matches = body.match(/type=(.+?)\&/);
            console.log("Request type is", matches[1]);
            const requestType = matches[1];

            if (requestType === 'init') {
                const matches = body.match(/enckey=(.+?)\&/);
                encKey = matches[1];
                console.log("Setting enckey to", encKey);
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
        res.end("Hello world!");
    }
};

const server = https.createServer(options, requestListener);
server.listen(443, "0.0.0.0", () => {
    console.log("Server listening on 443");
});
