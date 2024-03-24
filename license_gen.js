const crypto = require('crypto');
const fs = require('node:fs');
const readline = require('node:readline');
const { stdin: input, stdout: output } = require('node:process');
const rl = readline.createInterface({ input, output });
rl.question("Enter your HWID: ", (user_input) => {
    hwid = user_input;

    const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SxoW83nU4qAbHXqjhal
MiU62ae79Ayv/EAmVfJEeCymJIpvtTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpx
G5INKIQnVi1ZE0YPP1GKUXN4nchM31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuP
o+iKQqwzKnE27Fyi0USLK82PfwCN0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFy
wREoekljDot8noMOQiBo0NgqmkLLK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tf
lr1yMFQ1eAdOJqnmM5YxCv4FsU2qpZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxd
oQIDAQAB
-----END PUBLIC KEY-----`;
    const privateKey = `'-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----'`;


    const randomBytes = crypto.randomBytes(10);
    const md5 = crypto.createHash('md5').update(randomBytes).digest('hex');
    const encryptedMd5 = Buffer.from(randomBytes).toString('base64');

    const cipher = crypto.createCipheriv('aes-256-cbc', md5, Buffer.from('ABCDEF0123456789'));
    let privatekeyPkcs1PemEnc = cipher.update(privateKey, 'utf8', 'base64');
    privatekeyPkcs1PemEnc += cipher.final('base64');

    const license = { "cardstr": "free-korepi", "expiry_time": Math.floor((Math.pow(2, 32) - 1) / 2), "hwid": hwid, "role": 25, "data_id": Math.floor(Math.random() * 100000), "user_id": Math.floor(Math.random() * 100000) };
    const encryptedLicense = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING }, JSON.stringify(license)).toString('base64');
    const packedLicense = JSON.stringify({ "encrypted.dat": encryptedLicense, "Encrypted.md5": encryptedMd5, "privatekey_pkcs1.pem.enc": privatekeyPkcs1PemEnc });

    fs.writeFileSync('enc.json', packedLicense);

    rl.close();
});
