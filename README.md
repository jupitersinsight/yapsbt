<h1 align="center">
  
Packet Sniffer :pig_nose:

</h1>
<div align="center">

[Documentation][wiki]&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Pull Requests][pr]&nbsp;&nbsp;&nbsp;|&nbsp;&nbsp;&nbsp;[Issues][issues]

![GitHub last commit][lastcommit] [![Pull Requests][img-pr-badge]][pr] [![License][img-license-badge]][license]

</div>

## About This Repository

This repo contains code for a packet sniffer and its plugins for analysis of live traffic and pcap files. 

## Installation

### Linux
You need Python and Scapy! On linux, run:
```
$ pip3 install scapy
```
Clone the repo:
```
$ git clone https://github.com/jupitersinsight/packet_sniffer
```
## Usage

-r, --read:  pcap file(s) to parse  
-b, --bpf: BPF syntax to filter packets  
-i, --interface:iInterface to read live packets from   
-a, --action: Specify which *plugin* function to call

The folder *plugins* contains the modules that hold the functions that can be passed as argument to the sniffer.

Example: packet-sniffer.py --read file.pcap --bpf 'tcp port 21' --action ftp_commands

<!--Links-->
[issues]:https://github.com/jupitersinsight/packet_sniffer/issues "packet-sniffer Issues ➶"
[pull-requests]:https://github.com/jupitersinsight/packet_sniffer/pulls "packet-sniffer Requests ➶"
[wiki]:https://github.com/jupitersinsight/packet_sniffer/wiki "packet-sniffer Documentation ➶"
[repo]:https://github.com/jupitersinsight/packet_sniffer "packet-sniffer Repository ➶"
[pr]:https://github.com/jupitersinsight/packet_sniffer/pulls "packet-sniffer Pull Requests ➶"
[license]:https://github.com/jupitersinsight/packet_sniffer/blob/master/LICENSE "packet-sniffer License File ➶"

<!--Badges-->
[lastcommit]:https://img.shields.io/github/last-commit/jupitersinsight/packet_sniffer?style=for-the-badge
[img-pr-badge]:https://img.shields.io/badge/PRs-welcome-orange.svg?style=for-the-badge&logo=data%3Aimage%2Fsvg%2Bxml%3Bbase64%2CPD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48c3ZnIGlkPSJzdmcyIiB3aWR0aD0iNjQ1IiBoZWlnaHQ9IjU4NSIgdmVyc2lvbj0iMS4wIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciPiA8ZyBpZD0ibGF5ZXIxIj4gIDxwYXRoIGlkPSJwYXRoMjQxNyIgZD0ibTI5Ny4zIDU1MC44N2MtMTMuNzc1LTE1LjQzNi00OC4xNzEtNDUuNTMtNzYuNDM1LTY2Ljg3NC04My43NDQtNjMuMjQyLTk1LjE0Mi03Mi4zOTQtMTI5LjE0LTEwMy43LTYyLjY4NS01Ny43Mi04OS4zMDYtMTE1LjcxLTg5LjIxNC0xOTQuMzQgMC4wNDQ1MTItMzguMzg0IDIuNjYwOC01My4xNzIgMTMuNDEtNzUuNzk3IDE4LjIzNy0zOC4zODYgNDUuMS02Ni45MDkgNzkuNDQ1LTg0LjM1NSAyNC4zMjUtMTIuMzU2IDM2LjMyMy0xNy44NDUgNzYuOTQ0LTE4LjA3IDQyLjQ5My0wLjIzNDgzIDUxLjQzOSA0LjcxOTcgNzYuNDM1IDE4LjQ1MiAzMC40MjUgMTYuNzE0IDYxLjc0IDUyLjQzNiA2OC4yMTMgNzcuODExbDMuOTk4MSAxNS42NzIgOS44NTk2LTIxLjU4NWM1NS43MTYtMTIxLjk3IDIzMy42LTEyMC4xNSAyOTUuNSAzLjAzMTYgMTkuNjM4IDM5LjA3NiAyMS43OTQgMTIyLjUxIDQuMzgwMSAxNjkuNTEtMjIuNzE1IDYxLjMwOS02NS4zOCAxMDguMDUtMTY0LjAxIDE3OS42OC02NC42ODEgNDYuOTc0LTEzNy44OCAxMTguMDUtMTQyLjk4IDEyOC4wMy01LjkxNTUgMTEuNTg4LTAuMjgyMTYgMS44MTU5LTI2LjQwOC0yNy40NjF6IiBmaWxsPSIjZGQ1MDRmIi8%2BIDwvZz48L3N2Zz4%3D
[img-license-badge]:https://img.shields.io/badge/license-gnu-367588.svg?style=for-the-badge