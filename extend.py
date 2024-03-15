import base64
import json
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from OpenSSL import crypto

enc_json = open("enc.json", "r")
enc_json = enc_json.read()
license = json.loads(enc_json)

encrypted_license_info = base64.b64decode(license['encrypted.dat'])

md5 = MD5.new()
md5.update(base64.b64decode(license['Encrypted.md5']))
priv_key_key = str.encode(md5.hexdigest())

encrypted_priv_key = base64.b64decode(license['privatekey_pkcs1.pem.enc'])

aes = AES.new(priv_key_key, AES.MODE_CBC, b'ABCDEF0123456789')
partial_key = aes.decrypt(encrypted_priv_key)
end = partial_key.rfind(b'\n')
key = partial_key[:end]
public_key = crypto.dump_publickey(crypto.FILETYPE_PEM, crypto.load_privatekey(crypto.FILETYPE_PEM, key)).decode()

rsa = RSA.importKey(key)
pub_rsa = RSA.importKey(public_key)

cipher = PKCS1_v1_5.new(rsa)
license_info = json.loads(cipher.decrypt(encrypted_license_info, 'bruh'))
license_info['expiry_time'] = (2**32 - 1) // 2
license_info = json.dumps(license_info)

pub_cipher = PKCS1_v1_5.new(pub_rsa)
license['encrypted.dat'] = base64.b64encode(pub_cipher.encrypt(license_info.encode())).decode()

extended_enc_json = open("ext_enc.json", "w")
extended_enc_json.write(json.dumps(license))
