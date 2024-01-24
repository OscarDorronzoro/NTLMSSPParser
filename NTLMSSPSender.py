from Crypto.Hash import MD4, HMAC
import random
import datetime
from sys import argv
import base64

def type1Sender():
    flagsDefault = b'\x07\x82\x08\x00'
    '''
    Flags
    0x00080000 - Negotiate NTLM2 Key 
    0x00008000 - Negotiate Always Sign 
    0x00000200 - Negotiate NTLM 
    0x00000004 - Request Target 
    0x00000002 - Negotiate OEM 
    0x00000001 - Negotiate Unicode 
    '''

    domainSB = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    workstationSB = b'\x00\x00\x00\x00\x00\x00\x00\x00'

    return flagsDefault + domainSB + workstationSB

def type3Sender():
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
    blob += int.to_bytes(timestamp, length=8, byteorder='little')
    blob += clientNonce
    blob += b'\x00\x00\x00\x00'
    blob += targetInformation
    blob += b'\x00\x00\x00\x00'

    NTLMv2Response = HMAC.new(NTLMv2Hash, challenge + blob).digest()
    NTLMv2Response += blob 

    print(NTLMv2Response.hex())
    #print('cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301ffffff00112233440000000002000c0044004f004d00410049004e0001000c005300450052005600450052000400140064006f006d00610069006e002e0063006f006d00030022007300650072007600650072002e0064006f006d00610069006e002e0063006f006d000000000000000000')

    return b'NotImplemented'+ NTLMv2Response


def showHelp():
    print(
'''
Usage:

    python NTLMSSPSender.py <NTLM message type (1 or 3)>

    Flags:
        --help: show this message
'''
    )

def main():
    if len(argv) != 2 or argv[1] == '--help':
        showHelp()
        return
    
    messageType = int(argv[1])
    if messageType != 1 and messageType != 3:
        showHelp()
        return
    
    signature = 'NTLMSSP'.encode() + b'\x00'
    messageTypeLittle = int.to_bytes(messageType, length=4, byteorder='little')

    message = signature + messageTypeLittle
    
    if messageType == 1:
        message += type1Sender()
    if messageType == 3:
        message += type3Sender()

    print(message)

    base64Message = base64.b64encode(message).decode()
    print(base64Message)

    print('WWW-Authenticate: NTLM', base64Message)


if __name__ == '__main__':
    main()