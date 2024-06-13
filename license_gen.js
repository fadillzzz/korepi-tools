const crypto = require("crypto");
const fs = require("node:fs");
const readline = require("node:readline");
const { stdin: input, stdout: output } = require("node:process");
const rl = readline.createInterface({ input, output });
rl.question("Enter your HWID: ", (user_input) => {
  //   hwid = user_input;
  hwid = "---------Hi-Korepi-Devs---------";

  const publicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuBti5eEFCv3+qcBnooMF
vNHH2lDD/GjcgNpQNaeow7bCawpHMkyxtUUVQjuhyo5+LT7lMOJ+yoQAE5507Cvn
Ep9tuSJC0qcVT4/07FLblTDJiYxFgsFd5/skmUDTmClgffr8UOPRvJp/q62GTyYa
Pb63jWPHbNhqVjjWCI/ZRnfzqkadiP9uzdTVvyLkLpj6Hr/LpvHRUlK/NGhh1QU7
8lIc87XmNzOVL+uzMAT00AcKzilwg0za/oG5SXeHdac53t0lN3Bge5VxVgyzh0M2
/ADipBfd2JzlElNUL0y45Kx/HopT3nfwoq5PHW3JFXLxg56l3U8LqedK7Q+K7jmP
/QIDAQAB
-----END PUBLIC KEY-----`;
  const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC4G2Ll4QUK/f6p
wGeigwW80cfaUMP8aNyA2lA1p6jDtsJrCkcyTLG1RRVCO6HKjn4tPuUw4n7KhAAT
nnTsK+cSn225IkLSpxVPj/TsUtuVMMmJjEWCwV3n+ySZQNOYKWB9+vxQ49G8mn+r
rYZPJho9vreNY8ds2GpWONYIj9lGd/OqRp2I/27N1NW/IuQumPoev8um8dFSUr80
aGHVBTvyUhzzteY3M5Uv67MwBPTQBwrOKXCDTNr+gblJd4d1pzne3SU3cGB7lXFW
DLOHQzb8AOKkF93YnOUSU1QvTLjkrH8eilPed/Cirk8dbckVcvGDnqXdTwup50rt
D4ruOY/9AgMBAAECggEAAtZZNdW78Clt7UvLzRNb2UcaX2DzREaRb2Lt7YXB8hI0
+NVVt467BmIkK7sjiS2dADGB8rjq31AdeC/u+VzL2NugI0RF510v1OQREDtOqwPv
dzE0OQml2tdh/wKiwCuTEx31GYIJT3DKGuk3sqyRpvXzejhZcHH9YYrKsaMV5CIa
bDGikaoqEBCSXHT8SL2bOgf2tTX1szwR/Yn8GQDEgHwPlw3B41jSgOvUf9L52VZy
ih5QxzQPzoT7DhMZ+LzPEAbvb80dMbT0TXVXLAYyrc+UOyw1Brtx1HSCTJ9K0naQ
bazm0mq//6nokJagtwUC9Zt8HlyZmE0Q+Cb2diuT+QKBgQDZbKljoDDUPYLXbpnw
rx76p58h0M5i7UTjodadIfXPDxZNP40poHUGQ0QNrned6JB7HSYe6hxLqV14AO6A
EaVlmQLbHJvhk+/3sohjBgYiLX1GngAB9yeId7cHgpgmFKoX47E9ZF2zqWzcnMSU
/kuhQBVPO8vQbecEmbj7SwJpiwKBgQDYxXT8PckYuz+izmtcgISm2CgUgExDAL1z
wDMQfRs10ly+L4I5hVQkBu5BunYaf/lhatb9EBsDRbvvZmePSfSzHEjvrzidnpxZ
FzABE+a5jpNQTPPQ/z98Dx5jtOt2fIV46Wbm/4ikyiJ3cioj9UIvqdLprgD2EDzI
zghWkvvNlwKBgQCztBsA68rP8RMuqgx0INmzBE4DbgjXPRJ+Lioq74GyJN8i887h
w+xVQ82AnV3iVvDrwLjcPlUquA43/FUj5vHUWjZBEZFJTbO9/4K4jacOIpjzf+2z
siqroX7WpzrH5rZ7TkcU3dqQfw0p/iyAlPm/ii7SsTKQz/VsGP4KPQH+ZwKBgEtO
zgWTsXlWFBWLgODyBSOxlLsKl3PvneHIs/TWgc2A95dbCfLRzxl1DvDmxoEOVKTz
aR0hq0DHyTKycOfm2YwgF3ateQ3JPKf21kaJk26Dicor8ch55KRE3FnnUKYpPHV1
ILq/q8kUMEUu9FTpr8S/SvbD7LGPko5whZUOG0yhAoGAK4VieEUXlxQeaI2JNQE+
loHWRKnvVCnFUs7qsalQB5yvs/3kr7n9usgGhAtC0IpIwyp1D7v2Om+AjAZLbvXi
EO6b4mHx2yTVODNwlDr1l5yvP20gqTDLIZb/fcIRxvnZKmEn0st7d7+5/NVUsGYv
JuXe/NYkDOj7sJowggbhASU=
-----END PRIVATE KEY-----`;

  //   const randomBytes = crypto.randomBytes(10);
  const randomBytes = Buffer.from("mokPVuACUwR5Qw==", "base64");
  const md5 = crypto.createHash("md5").update(randomBytes).digest("hex");
  const encryptedMd5 = Buffer.from(randomBytes).toString("base64");

  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    md5,
    Buffer.from("6BCDEF0123456786")
  );
  let privatekeyPkcs1PemEnc = cipher.update(privateKey, "utf8", "base64");
  privatekeyPkcs1PemEnc += cipher.final("base64");

  const license = {
    cardstr: "micah-oc-00000000000000000000000000000000",
    expiry_time: Math.floor((Math.pow(2, 32) - 1) / 2),
    hwid: hwid,
    role: 25,
    data_id: 44262,
    user_id: Math.floor(Math.random() * 100000),
  };
  const encryptedLicense = crypto
    .publicEncrypt(
      { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
      JSON.stringify(license)
    )
    .toString("base64");
  const packedLicense = JSON.stringify({
    "encrypted.dat": encryptedLicense,
    "Encrypted.md5": encryptedMd5,
    "privatekey_pkcs1.pem.enc": privatekeyPkcs1PemEnc,
  });

  fs.writeFileSync("enc.json", packedLicense);

  rl.close();
});
