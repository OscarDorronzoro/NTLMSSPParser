import base64
import datetime
from sys import argv

# NTLM Spec: https://davenport.sourceforge.net/ntlm.html


FLAGS = '''0x00000001	Negotiate Unicode 	Indicates that Unicode strings are supported for use in security buffer data.
0x00000002	Negotiate OEM 	Indicates that OEM strings are supported for use in security buffer data.
0x00000004	Request Target 	Requests that the server's authentication realm be included in the Type 2 message.
0x00000008	unknown 	This flag's usage has not been identified.
0x00000010	Negotiate Sign 	Specifies that authenticated communication between the client and server should carry a digital signature (message integrity).
0x00000020	Negotiate Seal 	Specifies that authenticated communication between the client and server should be encrypted (message confidentiality).
0x00000040	Negotiate Datagram Style 	Indicates that datagram authentication is being used.
0x00000080	Negotiate Lan Manager Key 	Indicates that the Lan Manager Session Key should be used for signing and sealing authenticated communications.
0x00000100	Negotiate Netware 	This flag's usage has not been identified.
0x00000200	Negotiate NTLM 	Indicates that NTLM authentication is being used.
0x00000400	unknown 	This flag's usage has not been identified.
0x00000800	Negotiate Anonymous 	Sent by the client in the Type 3 message to indicate that an anonymous context has been established. This also affects the response fields (as detailed in the "Anonymous Response" section).
0x00001000	Negotiate Domain Supplied 	Sent by the client in the Type 1 message to indicate that the name of the domain in which the client workstation has membership is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
0x00002000	Negotiate Workstation Supplied 	Sent by the client in the Type 1 message to indicate that the client workstation's name is included in the message. This is used by the server to determine whether the client is eligible for local authentication.
0x00004000	Negotiate Local Call 	Sent by the server to indicate that the server and client are on the same machine. Implies that the client may use the established local credentials for authentication instead of calculating a response to the challenge.
0x00008000	Negotiate Always Sign 	Indicates that authenticated communication between the client and server should be signed with a "dummy" signature.
0x00010000	Target Type Domain 	Sent by the server in the Type 2 message to indicate that the target authentication realm is a domain.
0x00020000	Target Type Server 	Sent by the server in the Type 2 message to indicate that the target authentication realm is a server.
0x00040000	Target Type Share 	Sent by the server in the Type 2 message to indicate that the target authentication realm is a share. Presumably, this is for share-level authentication. Usage is unclear.
0x00080000	Negotiate NTLM2 Key 	Indicates that the NTLM2 signing and sealing scheme should be used for protecting authenticated communications. Note that this refers to a particular session security scheme, and is not related to the use of NTLMv2 authentication. This flag can, however, have an effect on the response calculations (as detailed in the "NTLM2 Session Response" section).
0x00100000	Request Init Response 	This flag's usage has not been identified.
0x00200000	Request Accept Response 	This flag's usage has not been identified.
0x00400000	Request Non-NT Session Key 	This flag's usage has not been identified.
0x00800000	Negotiate Target Info 	Sent by the server in the Type 2 message to indicate that it is including a Target Information block in the message. The Target Information block is used in the calculation of the NTLMv2 response.
0x01000000	unknown 	This flag's usage has not been identified.
0x02000000	unknown 	This flag's usage has not been identified.
0x04000000	unknown 	This flag's usage has not been identified.
0x08000000	unknown 	This flag's usage has not been identified.
0x10000000	unknown 	This flag's usage has not been identified.
0x20000000	Negotiate 128 	Indicates that 128-bit encryption is supported.
0x40000000	Negotiate Key Exchange 	Indicates that the client will provide an encrypted master key in the "Session Key" field of the Type 3 message.
0x80000000	Negotiate 56 	Indicates that 56-bit encryption is supported.'''

flagLines = FLAGS.split('\n')
flagLines = flagLines[::-1]
#print(flagLines)

for i in range(len(flagLines)):
    flagLines[i] = flagLines[i].split('\t')
    #print(f[0])

WINDOWS_VERSIONS = [ # Major, Minor, Build, Description
    [3, 1, 528, 'Windows NT 3.1'],
    [3, 5, 807, 'Windows NT 3.5'],
    [3, 51, 1057, 'Windows NT 3.51'],
    [4, 0, 1381, 'Windows NT 4.0'],
    [5, 0, 2195, 'Windows 2000'],
    [5, 1, 2600, 'Windows XP'],
    [5, 2, 3790, 'Windows Server 2003'],
    [6, 0, 6000, 'Windows Vista'],
    [6, 0, 6001, 'Windows Server 2008'],
    [6, 1, 7600, 'Windows 7'],
    [6, 1, 8400, 'Windows Home Server 2011'],
    [6, 2, 9200, 'Windows Server 2012'],
    [6, 3, 9600, 'Windows Server 2012 R2']
]

def getWindowsVersion(major, minor, build):
    description = 'NOT FOUND'
    for v in WINDOWS_VERSIONS:
        if v[0] == major and v[1] == minor and v[2] == build:
            description = v[3]
            break
    return description

TARGET_INFORMATION_TYPES = [
    'Terminator',
    'Server Name',
    'Domain Name',
    'Fully-qualified DNS Host Name',
    'DNS Host Name',
    'Parent DNS Domain' # for servers in subdomains
]

def printFlags(flags):
    for i in range(len(flags)):
        if i % 8 == 0:
            print()
        elif i % 4 == 0:
            print(end=' ')
        print(flags[i], end=' ')
    print()
    print()

def readFlags(flags):
    flagInt = int.from_bytes(flags, byteorder='little')
    returnFlags = []
    for i in range(8*4 - 1, -1, -1):
        returnFlags.append(flagInt >> i & 1)
    return returnFlags

def readSecurityBuffer(sb):
    sbLength = int.from_bytes(sb[:2], byteorder='little')
    sbAllocated = int.from_bytes(sb[2:4], byteorder='little')
    sbOffset = int.from_bytes(sb[4:8], byteorder='little')
    return {'length': sbLength, 'allocated': sbAllocated, 'offset': sbOffset}

def printFlags(flags):
    print('\nFlags')
    for i in range(len(flags)):
        if flags[i] == 1:
            print(flagLines[i][0], '-', flagLines[i][1])
    print()

def readTargetInformation(targetInfo):
    baseIndex = 0
    targetInfoType = int.from_bytes(targetInfo[baseIndex:2], byteorder='little')
    
    targets = []
    while targetInfoType != 0 and targetInfo:
        targetInfoLength = int.from_bytes(targetInfo[baseIndex+2:baseIndex+4], byteorder='little')
        targetInfoContent = targetInfo[baseIndex+4:baseIndex+4+targetInfoLength]
    
        targets.append({
            'type': targetInfoType,
            'length': targetInfoLength,
            'content': targetInfoContent
        })
        
        baseIndex += 4 + targetInfoLength
        targetInfoType = int.from_bytes(targetInfo[baseIndex:baseIndex+2], byteorder='little')

    return targets

def type1Parser(bytesM1NTLM):
    M1Flagsbits = readFlags(bytesM1NTLM[12:16])
    printFlags(M1Flagsbits)


    M1DomainSB = readSecurityBuffer(bytesM1NTLM[16:24]) # Domain Security Buffer
    M1WorkstationSB = readSecurityBuffer(bytesM1NTLM[24:32]) # Workstation Security Buffer

    print('Domain Security Buffer (Length/Allocated Space/Offset):', M1DomainSB['length'], M1DomainSB['allocated'], M1DomainSB['offset'])
    print('Workstation Security Buffer (Length/Allocated Space/Offset):', M1WorkstationSB['length'], M1WorkstationSB['allocated'], M1WorkstationSB['offset'])


    print('\nRaw:', bytesM1NTLM)
    print('Length:', len(bytesM1NTLM))


def type2Parser(bytesM2NTLM):
    M2TargetNameSB = readSecurityBuffer(bytesM2NTLM[12:20])
    print('\nTarget Name Security Buffer (Length/Allocated Space/Offset):', M2TargetNameSB['length'], M2TargetNameSB['allocated'], M2TargetNameSB['offset'])

    M2Flagsbits = readFlags(bytesM2NTLM[20:24])
    printFlags(M2Flagsbits)

    M2Challenge = bytesM2NTLM[24:32]
    print('Challenge:', M2Challenge)

    M2Context = bytesM2NTLM[32:40]
    print('Context:', M2Context)

    M2TargetInformationSB = readSecurityBuffer(bytesM2NTLM[40:48])
    print('Target Information Security Buffer (Length/Allocated Space/Offset):', M2TargetInformationSB['length'], M2TargetInformationSB['allocated'], M2TargetInformationSB['offset'])


    M2OSVersionStructure = bytesM2NTLM[48:56]
    M2OSMajorVersion = int.from_bytes(M2OSVersionStructure[:1], byteorder='little')
    M2OSMinorVersion = int.from_bytes(M2OSVersionStructure[1:2], byteorder='little')
    M2OSBuildNumber = int.from_bytes(M2OSVersionStructure[2:4], byteorder='little')
    M2OSReserved = M2OSVersionStructure[4:8]
    OSVersionDescription = getWindowsVersion(M2OSMajorVersion, M2OSMinorVersion, M2OSBuildNumber)
    
    print('\nOS Version Structure:', f'{M2OSMajorVersion}.{M2OSMinorVersion} (Build {M2OSBuildNumber}) - {OSVersionDescription} - {M2OSReserved.hex()}')


    M2TargetName = bytesM2NTLM[M2TargetNameSB['offset']:M2TargetNameSB['offset']+M2TargetNameSB['length']]
    print('\nTarget Name:', M2TargetName.decode('utf-16'))


    M2TargetInformation = bytesM2NTLM[M2TargetInformationSB['offset']:M2TargetInformationSB['offset']+M2TargetInformationSB['length']]
    targets = readTargetInformation(M2TargetInformation)

    print('\nTargets Information')
    for t in targets:
        print('Target Information Type:', t['type'], TARGET_INFORMATION_TYPES[t['type']])
        print('Target Information Length:', t['length'])
        print('Target Information Content:', t['content'].decode('utf-16'))
        print()


    print('\nRaw:', bytesM2NTLM)
    print('Length:', len(bytesM2NTLM))


def type3Parser(bytesM3NTLM):
    M3LMSB = readSecurityBuffer(bytesM3NTLM[12:20])
    print('\nLM Security Buffer (Length/Allocated Space/Offset):', M3LMSB['length'], M3LMSB['allocated'], M3LMSB['offset'])

    M3NTLMSB = readSecurityBuffer(bytesM3NTLM[20:28])
    print('NTLM Security Buffer (Length/Allocated Space/Offset):', M3NTLMSB['length'], M3NTLMSB['allocated'], M3NTLMSB['offset'])

    M3TargetSB = readSecurityBuffer(bytesM3NTLM[28:36])
    print('Target Security Buffer (Length/Allocated Space/Offset):', M3TargetSB['length'], M3TargetSB['allocated'], M3TargetSB['offset'])

    M3UserSB = readSecurityBuffer(bytesM3NTLM[36:44])
    print('User Security Buffer (Length/Allocated Space/Offset):', M3UserSB['length'], M3UserSB['allocated'], M3UserSB['offset'])

    M3WorkstationSB = readSecurityBuffer(bytesM3NTLM[44:52])
    print('Workstation Security Buffer (Length/Allocated Space/Offset):', M3WorkstationSB['length'], M3WorkstationSB['allocated'], M3WorkstationSB['offset'])

    M3SessionKeySB = readSecurityBuffer(bytesM3NTLM[52:60])
    print('Session Key Security Buffer (Length/Allocated Space/Offset):', M3SessionKeySB['length'], M3SessionKeySB['allocated'], M3SessionKeySB['offset'])


    M3Flagsbits = readFlags(bytesM3NTLM[60:64])
    printFlags(M3Flagsbits)

    M3LMHash = bytesM3NTLM[M3LMSB['offset']:M3LMSB['offset']+M3LMSB['length']]
    print('M3LMHash:', M3LMHash)


    M3NTLMResponse = bytesM3NTLM[M3NTLMSB['offset']:M3NTLMSB['offset']+M3NTLMSB['length']]
    M3NTLMHash = M3NTLMResponse[:16]
    print('\nM3NTLM Hash (NTLM response without blob):', M3NTLMHash)
    
    M3NTLMBlob = M3NTLMResponse[16:]

    M3BlobSignature = M3NTLMBlob[:4]
    M3BlobReserved = M3NTLMBlob[4:8]

    M3BlobTimestamp = int.from_bytes(M3NTLMBlob[8:16], byteorder='little')/10**7 #segundos desde 1/1/1601
    secondsFrom1601ToEpoch = 11644473600
    M3BlobTimestamp = datetime.datetime.fromtimestamp(M3BlobTimestamp - secondsFrom1601ToEpoch)

    M3BlobClientNonce = M3NTLMBlob[16:24]
    M3BlobUnknown = M3NTLMBlob[24:28]
    M3BlobTargetInformation = M3NTLMBlob[28:-4]
    M3BlobUnknown2 = M3NTLMBlob[-4:]

    #print('\nM3NTLM Blob:', M3NTLMBlob)
    print('\nBlob Signature:', M3BlobSignature)
    print('Blob Reserved:', M3BlobReserved)
    print('Blob Timestamp', M3BlobTimestamp)
    print('Blob Client Nonce', M3BlobClientNonce)
    print('Blob Unknown:', M3BlobUnknown)
    print('Blob Target Information:', M3BlobTargetInformation.decode('utf-16'))
    print('Blob unknown 2:', M3BlobUnknown2)


    M3Target = bytesM3NTLM[M3TargetSB['offset']:M3TargetSB['offset']+M3TargetSB['length']]
    print('\nM3Target:', M3Target)

    M3User = bytesM3NTLM[M3UserSB['offset']:M3UserSB['offset']+M3UserSB['length']]
    print('M3User:', M3User.decode('utf-16'))

    M3WorkStation = bytesM3NTLM[M3WorkstationSB['offset']:M3WorkstationSB['offset']+M3WorkstationSB['length']]
    print('M3WorkStation:', M3WorkStation.decode('utf-16'))

    M3SessionKey = bytesM3NTLM[M3SessionKeySB['offset']:M3SessionKeySB['offset']+M3SessionKeySB['length']]
    print('M3SessionKey:', M3SessionKey)


    print('\nRaw:', bytesM3NTLM)
    print('Length:', len(bytesM3NTLM))


def showHelp():
    print(
'''
Usage:

    python NTLMSSPParser.py <base64 Encoded NTLM message>

    Flags:
        --help: show this message
'''
    )

def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s.encode()
    except Exception:
        return False

def main():
    if len(argv) != 2 or argv[1] == '--help':
        showHelp()
        return
    
    ntlm_b64 = argv[1]
    if not isBase64(ntlm_b64):
        showHelp()
        return
    
    # Type 1 Message Example
    #ntlm_b64 = 'TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA='

    # Type 2 Message Example
    #ntlm_b64 = 'TlRMTVNTUAACAAAADAAMADgAAAAFgokCbeRb6dMqwYIAAAAAAAAAAJIAkgBEAAAABQLODgAAAA9NAEUATgBBAFIAQQACAAwATQBFAE4AQQBSAEEAAQASAFcASQBOAEYARQBJAEkAUwAxAAQAGABtAGUAbgBhAHIAYQAuAGwAbwBjAGEAbAADACwAdwBpAG4AZgBlAGkAaQBzADEALgBtAGUAbgBhAHIAYQAuAGwAbwBjAGEAbAAFABgAbQBlAG4AYQByAGEALgBsAG8AYwBhAGwAAAAAAA=='
    
    # Type 3 Message Example
    #ntlm_b64 = 'TlRMTVNTUAADAAAAGAAYAFgAAAC+AL4AcAAAAAAAAABAAAAAAgACAEAAAAAWABYAQgAAAAAAAAAAAAAABYIIAGEAVwBPAFIASwBTAFQAQQBUAEkATwBOAJSwJEhi5nh0Nhl4j/eBeIjIXqpiwibDMWXfzJFrkd047P8Soh4rHdoBAQAAAAAAAAB6WNj3P9oBFV6fbMhbIZAAAAAAAgAMAE0ARQBOAEEAUgBBAAEAEgBXAEkATgBGAEUASQBJAFMAMQAEABgAbQBlAG4AYQByAGEALgBsAG8AYwBhAGwAAwAsAHcAaQBuAGYAZQBpAGkAcwAxAC4AbQBlAG4AYQByAGEALgBsAG8AYwBhAGwABQAYAG0AZQBuAGEAcgBhAC4AbABvAGMAYQBsAAAAAAA='
    
    ntlm_bytes = base64.b64decode(ntlm_b64)
    
    signature = ntlm_bytes[:8].decode()
    messageType = int.from_bytes(ntlm_bytes[8:12], byteorder='little')
    
    print('\n\nSignature:', signature)
    print('Message Type:', messageType)
    
    if messageType == 1:
        type1Parser(ntlm_bytes)
    if messageType == 2:
        type2Parser(ntlm_bytes)
    if messageType == 3:
        type3Parser(ntlm_bytes)


if __name__ == '__main__':
    main()
