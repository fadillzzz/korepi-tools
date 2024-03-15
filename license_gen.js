const crypto = require('crypto');
const fs = require('node:fs');
const readline = require('node:readline');
const { stdin: input, stdout: output } = require('node:process');
const rl = readline.createInterface({ input, output });
rl.question("Enter your HWID: ", (user_input) => {
    hwid = user_input;

    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
    });

    const randomBytes = crypto.randomBytes(10);
    const md5 = crypto.createHash('md5').update(randomBytes).digest('hex');
    const encryptedMd5 = Buffer.from(randomBytes).toString('base64');

    const cipher = crypto.createCipheriv('aes-256-cbc', md5, Buffer.from('ABCDEF0123456789'));
    let privatekeyPkcs1PemEnc = cipher.update(privateKey, 'utf8', 'base64');
    privatekeyPkcs1PemEnc += cipher.final('base64');

    const license = { "cardstr": "free-korepi", "expiry_time": Math.floor((Math.pow(2, 32) - 1) / 2), "hwid": hwid, "role": 25, "data_id": 1, "user_id": 1 };
    const encryptedLicense = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, JSON.stringify(license)).toString('base64');
    const packedLicense = JSON.stringify({ "encrypted.dat": encryptedLicense, "Encrypted.md5": encryptedMd5, "privatekey_pkcs1.pem.enc": privatekeyPkcs1PemEnc });

    fs.writeFileSync('enc.json', packedLicense);

    rl.close();
});
