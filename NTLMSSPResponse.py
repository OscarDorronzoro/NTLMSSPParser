from Crypto.Hash import MD4, HMAC
import random
import datetime

target = 'DOMAIN'
username = 'user'
password = 'SecREt01'.encode('utf-16')[2:]
challenge = bytes.fromhex('0123456789abcdef')
targetInformation = bytes.fromhex('02000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d0000000000')
clientNonce = bytes.fromhex('ffffff0011223344')
clientNonce = random.randbytes(8)
timeFrom1601 = 11644473600 * 10**7
timestamp = 127003176000000000
timestamp = int(datetime.datetime.timestamp(datetime.datetime.now())*10**7) + timeFrom1601

NTLMHash = MD4.new(password).digest()

userTarget = username.upper() + target
userTarget = userTarget.encode('utf-16')[2:]

NTLMv2Hash = HMAC.new(NTLMHash, userTarget).digest()

blob = b'\x01\x01\x00\x00'
blob += b'\x00\x00\x00\x00'
blob += int.to_bytes(timestamp,length=8, byteorder='little')
blob += clientNonce
blob += b'\x00\x00\x00\x00'
blob += targetInformation
blob += b'\x00\x00\x00\x00'

NTLMv2Response = HMAC.new(NTLMv2Hash, challenge + blob).digest()
NTLMv2Response += blob 

print(NTLMv2Response.hex())

print('cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301ffffff00112233440000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000000000000')

