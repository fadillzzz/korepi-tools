const https = require('https');
const fs = require('fs');
const crypto = require('crypto');

const options = {
    key: fs.readFileSync('certs/md5c.korepi.com.key'),
    cert: fs.readFileSync('certs/md5c.korepi.com.crt'),
    ca: [fs.readFileSync('certs/md5c.korepi.com.crt')],
};

const license = require('./enc.json');

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

const requestListener = function (req, res) {
    console.log(new Date().toISOString() + ': ' + req.headers.host + req.url);

    if (req.url.indexOf('/prod-api/online/subscribe/md5verify') !== -1) {
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
    } else {
        res.end("Hello world!");
    }
};

const server = https.createServer(options, requestListener);
server.listen(443, "0.0.0.0", () => {
    console.log("Server listening on 443");
});
