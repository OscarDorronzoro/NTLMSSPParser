import base64
import datetime

def printFlags(flags):
    for i in range(len(flags)):
        if i % 8 == 0:
            print()
        elif i % 4 == 0:
            print(end=' ')
        print(flags[i], end=' ')
    print()
    print()

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


b64M1NTLM = 'TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA='

bytesM1NTLM = base64.b64decode(b64M1NTLM)
M1Signature = bytesM1NTLM[:8].decode()
M1MessageType = int.from_bytes(bytesM1NTLM[8:12], byteorder='little')

def readFlags(flags):
    flagInt = int.from_bytes(flags, byteorder='little')
    returnFlags = []
    for i in range(8*4 - 1, -1, -1):
        returnFlags.append(flagInt >> i & 1)
    return returnFlags

M1Flags = bytesM1NTLM[12:16][::-1]
M1Flagsbits = readFlags(bytesM1NTLM[12:16])

def readSecurityBuffer(sb):
    sbLength = int.from_bytes(sb[:2], byteorder='little')
    sbAllocated = int.from_bytes(sb[2:4], byteorder='little')
    sbOffset = int.from_bytes(sb[4:8], byteorder='little')
    return sbLength, sbAllocated, sbOffset

M1DomainSBLength, M1DomainSBAllocated, M1DomainSBOffset = readSecurityBuffer(bytesM1NTLM[16:24])
M1WorkstationSBLength, M1WorkstationSBAllocated, M1WorkstationSBOffset = readSecurityBuffer(bytesM1NTLM[24:32])


print(M1Signature)
print('Message Type:',M1MessageType)

#print(M1Flags)
#printFlags(M1Flagsbits)
def printFlags(flags):
    print('\nFlags')
    for i in range(len(flags)):
        if flags[i] == 1:
            print(flagLines[i][0], '-', flagLines[i][1])
    print()

printFlags(M1Flagsbits)

print('Domain Security Buffer (Length/Allocated Space/Offset):', M1DomainSBLength, M1DomainSBAllocated, M1DomainSBOffset)
print('Workstation Security Buffer (Length/Allocated Space/Offset):', M1WorkstationSBLength, M1WorkstationSBAllocated, M1WorkstationSBOffset)

print()
print('Raw:', bytesM1NTLM)
print('Length:', len(bytesM1NTLM))
print('\n\n')



b64M3NTLM = 'TlRMTVNTUAADAAAAGAAYAGgAAAC+AL4AgAAAAAAAAABAAAAAEgASAEAAAAAWABYAUgAAAAAAAAAAAAAABYIIAGEAbgBvAG4AeQBtAG8AdQBzAFcATwBSAEsAUwBUAEEAVABJAE8ATgCszO3gEs+FCQPG+EPwbBACp2iYkCMetY1rHCFDtOy+TXBPJZrQdeGLAQEAAAAAAAAApvubhC/aAcK5uGDnbYsoAAAAAAIADABNAEUATgBBAFIAQQABABIAVwBJAE4ARgBFAEkASQBTADIABAAYAG0AZQBuAGEAcgBhAC4AbABvAGMAYQBsAAMALAB3AGkAbgBmAGUAaQBpAHMAMgAuAG0AZQBuAGEAcgBhAC4AbABvAGMAYQBsAAUAGABtAGUAbgBhAHIAYQAuAGwAbwBjAGEAbAAAAAAA'

bytesM3NTLM = base64.b64decode(b64M3NTLM)
M3Signature = bytesM3NTLM[:8].decode()
M3MessageType = int.from_bytes(bytesM3NTLM[8:12], byteorder='little')

M3LMSBLength, M3LMSBAllocated, M3LMSBOffset = readSecurityBuffer(bytesM3NTLM[12:20])
M3NTLMSBLength, M3NTLMSBAllocated, M3NTLMSBOffset = readSecurityBuffer(bytesM3NTLM[20:28])
M3TargetSBLength, M3TargetSBAllocated, M3TargetSBOffset = readSecurityBuffer(bytesM3NTLM[28:36])
M3UserSBLength, M3UserSBAllocated, M3UserSBOffset = readSecurityBuffer(bytesM3NTLM[36:44])
M3WorkstationSBLength, M3WorkstationSBAllocated, M3WorkstationSBOffset = readSecurityBuffer(bytesM3NTLM[44:52])
M3SessionKeySBLength, M3SessionKeySBAllocated, M3SessionKeySBOffset = readSecurityBuffer(bytesM3NTLM[52:60])

M3Flagsbits = readFlags(bytesM3NTLM[60:64])

M3LMHash = bytesM3NTLM[M3LMSBOffset:M3LMSBOffset+M3LMSBLength]

M3NTLMHash = bytesM3NTLM[M3NTLMSBOffset:M3NTLMSBOffset+M3NTLMSBLength]
M3NTLMResponse = M3NTLMHash[:16]
M3NTLMBlob = M3NTLMHash[16:]
M3BlobSignature = M3NTLMBlob[:4]
M3BlobReserved = M3NTLMBlob[4:8]

M3BlobTimestamp = int.from_bytes(M3NTLMBlob[8:16], byteorder='little')/10**7 #segundos desde 1/1/1601
secondsFrom1601ToEpoch = 11644473600
M3BlobTimestamp = datetime.datetime.fromtimestamp(M3BlobTimestamp - secondsFrom1601ToEpoch)

M3BlobClientNonce = M3NTLMBlob[16:24]
M3BlobUnknown = M3NTLMBlob[24:28]
M3BlobTargetInformation = M3NTLMBlob[28:-4]
M3BlobUnknown2 = M3NTLMBlob[-4:]


M3Target = bytesM3NTLM[M3TargetSBOffset:M3TargetSBOffset+M3TargetSBLength]
M3User = bytesM3NTLM[M3UserSBOffset:M3UserSBOffset+M3UserSBLength]
M3WorkStation = bytesM3NTLM[M3WorkstationSBOffset:M3WorkstationSBOffset+M3WorkstationSBLength]
M3SessionKey = bytesM3NTLM[M3SessionKeySBOffset:M3SessionKeySBOffset+M3SessionKeySBLength]

print(M3Signature)
print('Message Type:',M3MessageType)
print()

print('LM Security Buffer (Length/Allocated Space/Offset):', M3LMSBLength, M3LMSBAllocated, M3LMSBOffset)
print('NTLM Security Buffer (Length/Allocated Space/Offset):', M3NTLMSBLength, M3NTLMSBAllocated, M3NTLMSBOffset)
print('Target Security Buffer (Length/Allocated Space/Offset):', M3TargetSBLength, M3TargetSBAllocated, M3TargetSBOffset)
print('User Security Buffer (Length/Allocated Space/Offset):', M3UserSBLength, M3UserSBAllocated, M3UserSBOffset)
print('Workstation Security Buffer (Length/Allocated Space/Offset):', M3WorkstationSBLength, M3WorkstationSBAllocated, M3WorkstationSBOffset)
print('Session Key Security Buffer (Length/Allocated Space/Offset):', M3SessionKeySBLength, M3SessionKeySBAllocated, M3SessionKeySBOffset )
print()

printFlags(M3Flagsbits)

print('M3LMHash:', M3LMHash)

print('M3NTLM Hash:', M3NTLMResponse)
#print('M3NTLM Blob:', M3NTLMBlob)
print('Blob Signature:', M3BlobSignature)
print('Blob Reserved:', M3BlobReserved)
print('Blob Timestamp', M3BlobTimestamp)
print('Blob Client Nonce', M3BlobClientNonce)
print('Blob Unknown:', M3BlobUnknown)
print('Blob Target Information:', M3BlobTargetInformation.decode('utf-16'))
print('Blob unknown 2:', M3BlobUnknown2)

print('M3Target:', M3Target)
print('M3User:', M3User.decode('utf-16'))
print('M3WorkStation:', M3WorkStation.decode('utf-16'))
print('M3SessionKey:', M3SessionKey)

print()
print('Raw:', bytesM3NTLM)
print('Length:', len(bytesM3NTLM))

