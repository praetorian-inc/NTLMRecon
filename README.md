# Overview
NTLMRecon is a Golang version of the original NTLMRecon utility written by Sachin Kamath (AKA pwnfoo). NTLMRecon can be leveraged to perform brute forcing against a targeted webserver to identify common application endpoints supporting NTLM authentication. This includes endpoints such as the Exchange Web Services endpoint which can often be leveraged to bypass multi-factor authentication. 

The tool supports collecting metadata from the exposed NTLM authentication endpoints including information on the computer name, Active Directory domain name, and Active Directory forest name. This information can be obtained without prior authentication by sending an NTLM NEGOTIATE_MESSAGE packet to the server and examining the NTLM CHALLENGE_MESSAGE returned by the targeted server. We have also published a blog post alongside this tool discussing some of the motiviations behind it's development and how we are approaching more advanced metadata collectoin within Chariot. 

# Why build a new version of this capability?

We wanted to perform brute-forcing and automated identification of exposed NTLM authentication endpoints within Chariot, our external attack surface management and continuous automated red teaming platform. Our primary backend scanning infrastructure is written in Golang and we didn't want to have to download and shell out to the NTLMRecon utility in Python to collect this information. We also wanted more control over the level of detail of the information we collected, etc.

# Installation

The following command can be leveraged to install the NTLMRecon utility. Alternatively, you may download a precompiled version of the binary from the releases tab in GitHub.

```sh
go install github.com/praetorian-inc/NTLMRecon/cmd/NTLMRecon@latest
```

# Usage
The following command can be leveraged to invoke the NTLM recon utility and discover exposed NTLM authentication endpoints:

```sh
NTLMRecon -t https://autodiscover.contoso.com
```

The following command can be leveraged to invoke the NTLM recon utility and discover exposed NTLM endpoints while outputting collected metadata in a JSON format:

```sh
NTLMRecon -t https://autodiscover.contoso.com -o json
```

# Example JSON Output 

Below is an example JSON output with the data we collect from the NTLM CHALLENGE_MESSAGE returned by the server:

```json
{
  "url": "https://autodiscover.contoso.com/EWS/",
  "ntlm": {
    "netbiosComputerName": "MSEXCH1",
    "netbiosDomainName": "CONTOSO",
    "dnsDomainName": "na.contoso.local",
    "dnsComputerName": "msexch1.na.contoso.local",
    "forestName": "contoso.local"
  }
}
```

```sh
➜  ~ NTLMRecon -t https://adfs.contoso.com -o json | jq
{
  "url": "https://adfs.contoso.com/adfs/services/trust/2005/windowstransport",
  "ntlm": {
    "netbiosComputerName": "MSFED1",
    "netbiosDomainName": "CONTOSO",
    "dnsDomainName": "corp.contoso.com",
    "dnsComputerName": "MSEXCH1.corp.contoso.com",
    "forestName": "contoso.com"
  }
}
➜  ~ NTLMRecon -t https://autodiscover.contoso.com
https://autodiscover.contoso.com/Autodiscover
https://autodiscover.contoso.com/Autodiscover/AutodiscoverService.svc/root
https://autodiscover.contoso.com/Autodiscover/Autodiscover.xml
https://autodiscover.contoso.com/EWS/
https://autodiscover.contoso.com/OAB/
https://autodiscover.contoso.com/Rpc/
➜  ~
```

# Potential Additional Features

Our methodology when developing this tool has targeted the most barebones version of the desired capability for the initial release. The goal for this project was to create an initial tool we could integrate into Chariot and then allow community contributions and feedback to drive additional tooling improvements or functionality. Below are some ideas for additional functionality which could be added to NTLMRecon:

* Concurrency and Performance Improvements: There could be some additional improvements to concurrency and performance. Currently, the tool sequentially makes HTTP requests and waits for the previous request to be performed. 
* Batch Scanning Functionality: Another idea would be to extend the NTLMRecon utility to accept a list of hosts from standard input. One usage scenario for this could be an attacker running a combination of “subfinder | httpx | NTLMRecon” to enumerate HTTP servers and then identify NTLM authentication endpoints that are exposed externally across an entire attack surface.
* One-off Data Collection Capability: A user may wish to perform one-off data collection targeting a specific endpoint which is currently not supported by NTLMRecon.
* User-Agent Randomization or Control: A user may wish to randomize the user-agents used to make requests. Alternatively when targeting Microsoft Exchange servers sometimes using a user-agent with a mobile client or legacy third-party email client can allow requests to the /EWS/Exchange.asmx endpoint through, etc.

# References
[1] https://www.praetorian.com/blog/automating-the-discovery-of-ntlm-authentication-endpoints/

