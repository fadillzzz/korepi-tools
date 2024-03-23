const fs = require('fs');
const forge = require('node-forge');
const crypto = require('crypto');

async function generateSelfSignedCerts() {
    if (!fs.existsSync('certs')) {
        fs.mkdirSync('certs');
    }

    // openssl req -x509 -days 3650 -key ca_private_key.pem -out ca_cert.pem
    // openssl req -new -key my_private_key.pem -out my_cert_req.pem
    // openssl x509 -req -in my_cert_req.pem -days 3650 -CA ca_cert.pem -CAkey ca_private_key.pem -CAcreateserial -out my_signed_cert.pem -extfile config

    const keyPair = await forge.pki.rsa.generateKeyPair(4096);
    const cert = forge.pki.createCertificate();
    cert.publicKey = keyPair.publicKey;
    cert.serialNumber = '01';
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

    const attrs = [
        { name: 'commonName', value: 'md5c.korepi.com' },
        { name: 'countryName', value: 'US' },
        { shortName: 'ST', value: 'California' },
        { name: 'localityName', value: 'San Francisco' },
        { name: 'organizationName', value: 'Korepi' },
        { shortName: 'OU', value: 'Korepi' }
    ];

    cert.setSubject(attrs);
    cert.setIssuer(attrs);
    cert.setExtensions([
        {
            name: 'basicConstraints',
            cA: false
        },
        {
            name: 'subjectAltName',
            altNames: [{
                type: 2,
                value: 'md5c.korepi.com'
            }, {
                type: 2,
                value: 'md5c.mxmicah.me'
            }, {
                type: 2,
                value: 'auth.btxo.cn'
            }]
        }
    ]);

    cert.sign(keyPair.privateKey, forge.md.sha256.create());

    const caCert = forge.pki.certificateToPem(cert);
    const caPrivateKey = forge.pki.privateKeyToPem(keyPair.privateKey);

    fs.writeFileSync('certs/md5c.korepi.com.crt', caCert);
    fs.writeFileSync('certs/md5c.korepi.com.key', caPrivateKey);
}

generateSelfSignedCerts();
