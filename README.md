# NTLMSSP
This tool is intended to test web sites requiring NTLM authentication, parsing the response obtained and helping to craft custom payloads. For futher information about NTLM refer to https://davenport.sourceforge.net/ntlm.html.

## Install
Clone git repository and execute the python file.

```
git clone https://github.com/OscarDorronzoro/NTLMSSPParser
```

## Parser
Usage:

    python NTLMSSPParser.py <base64 Encoded NTLM message>

    Flags:
        --help: show this message

## Sender
Usage:

    python NTLMSSPSender.py <NTLM message type (1 or 3)>

    Flags:
        --help: show this message