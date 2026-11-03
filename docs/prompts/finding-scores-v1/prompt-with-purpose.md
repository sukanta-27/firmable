I am working on an assignment that is working on building scoring and attribution of internet scanned data to find out which companies are at risk of an exploitation with the goal of updating those businesses with an email telling them about the vulnerability. This is a usecase that can be used for a lot of good usecases, as it detects threats early before an attacker can take the advantage and expose these businesses and their innocent clients.


You are assessing findings from an internet-wide scan, to decide how urgently an organisation that has each finding needs security help. For each item, answer three questions using only the definitions below. Judge the finding as described; assume it is real. Don't consider which organisation has it.

## The questions

**exploitation**: `active` · `poc` · `none`
- `active`: credible public reports that attackers exploit this flaw, or abuse this kind of exposure, in the wild (mass scanning, compromise or ransom campaigns).
- `poc`: a public method or tool exists, but no credible reports of widespread abuse.
- `none`: no public method; it weakens security without a known direct way to abuse it.

**automatable**: `yes` · `no`
- `yes` if an attacker can go from finding this on the internet to the impact with no per-target human effort: no tricking a user, no guessing a secret specific to the target, no sitting on the victim's network path, no chaining with another unknown flaw.

**technical_impact**: `total` · `partial` · `information`
- `total`: full control of the system, or read or change all the data it holds.
- `partial`: limited control, or some of the data.
- `information`: reveals details (versions, names, settings) that help a later attack but give no control or data by themselves.

When you are torn between two levels, choose the lower one and say why in `reason`. If the description is not enough to answer, set `answerable` to false and explain; don't guess.

Return only a JSON array, one object per item, in input order:
`{"item_id", "answerable", "exploitation", "automatable", "technical_impact", "reason", "salesperson_line"}`
`reason`: at most two sentences, naming the attack path. `salesperson_line`: at most 25 words, plain English, no jargon, saying what an attacker could do.

## Items

Each item has an `item_id`, a `kind` (`exposure` or `vulnerability`), a `description` of what the scanner found, and up to two `evidence` excerpts from real scan replies.

[
 {
  "item_id": "heartbleed_vulnerable",
  "kind": "exposure",
  "description": "A TLS service answered a Heartbleed test (CVE-2014-0160) in a way that shows it leaks the contents of its memory.",
  "evidence": [
   "2026/10/26 12:17:07 ([]uint8) {\n 00000000  02 00 74 63 65 6e 73 75  73 2e 73 68 6f 64 61 6e  |..tcensus.shodan|\n 00000010  2e 69 6f 53 45 43 55 52  49 54 59 20 53 55 52 56  |.ioSECURITY SURV|\n 00000020  45 59 96 e2 39 81 ae ac  74 c0 8c ea b9 42 63 38  |EY..9...t....Bc8|\n 00000030  6a 92 6a bd 70 a2",
   "2026/10/26 12:35:13 ([]uint8) {\n 00000000  02 00 74 63 65 6e 73 75  73 2e 73 68 6f 64 61 6e  |..tcensus.shodan|\n 00000010  2e 69 6f 53 45 43 55 52  49 54 59 20 53 55 52 56  |.ioSECURITY SURV|\n 00000020  45 59 94 bd dc d9 d8 96  63 9a cf 23 03 d9 e5 04  |EY......c..#....|\n 00000030  a7 f1 58 58 a5 69"
  ]
 },
 {
  "item_id": "tag_compromised",
  "kind": "exposure",
  "description": "The scanner marked the host as compromised: its reply shows signs that an attacker already controls it.",
  "evidence": [
   "database,eol-product,compromised | MongoDB Server Information\n{\n    \"process\": \"mongod\", \n    \"pid\": 1228, \n    \"connections\": {\n        \"current\": 1, \n        \"available\": 51199, \n        \"totalCreated\": 98195\n    }, \n    \"locks\": {\n ",
   "cloud,database,eol-product,compromised | HTTP/1.1 200 OK\r\nX-elastic-product: Elasticsearch\r\ncontent-type: application/json; charset=UTF-8\r\ncontent-length: 546\r\n\r\n\nElastic:\n  Total Size: 34.6 MB\n  Total Docs: 591\n  Indices:\n    3.0 (35.19 KB)"
  ]
 },
 {
  "item_id": "ransom_note",
  "kind": "exposure",
  "description": "A database or search index is named like a ransom note, or a web page asks for bitcoin to recover files: someone has already wiped or encrypted data and left a demand.",
  "evidence": [
   "databases: READ__ME_TO_RECOVER_YOUR_DATA",
   "indices: read_me"
  ]
 },
 {
  "item_id": "mongodb_noauth",
  "kind": "exposure",
  "description": "A MongoDB database answers queries without asking for a login.",
  "evidence": [
   "databases: local,READ__ME_TO_RECOVER_YOUR_DATA,admin | {\"authentication\":false,\"serverStatus\":{\"process\":\"mongod\",\"pid\":1228,\"connections\":{\"current\":1,\"available\":51199,\"totalCreated\":98195},\"locks\":{\"admin\":{\"timeAcquiringMicros\":{\"r\":993307,\"w\":0},\"timeLockedMicros\":{\"r\":10769154,\"w\":0}},\"README_",
   "databases: admin,local | {\"authentication\":false,\"serverStatus\":{\"process\":\"mongod\",\"pid\":1683,\"connections\":{\"current\":1,\"available\":51199,\"totalCreated\":1937},\"locks\":{\"Database\":{\"acquireCount\":{\"r\":1351351,\"R\":62,\"W\":7}},\"Global\":{\"acquireCount\":{\"r\":5404957,\"w\":7,\"W\":3}},\"Collection\":{\"acquireC"
  ]
 },
 {
  "item_id": "redis_noauth",
  "kind": "exposure",
  "description": "A Redis data store answers commands and shows its data without a password.",
  "evidence": [
   "keyspace: {\"db0\":\"keys=1,expires=0,avg_ttl=0,subexpiry=0\"} | {\"stats\":{\"eventloop_cycles\":19984224,\"active_defrag_hits\":0,\"total_reads_processed\":392771,\"rejected_connections\":0,\"active_defrag_key_hits\":0,\"client_query_buffer_limit_disconnections\":0,\"pubsub_patterns\":0,\"instantaneous_output_repl_kbp",
   "keyspace: {\"db1\":\"keys=341,expires=0,avg_ttl=0,subexpiry=0\",\"db0\":\"keys=100379,expires=10,avg_ttl=1576645410,subexpiry=0\"} | {\"stats\":{\"eventloop_cycles\":5528126,\"active_defrag_hits\":0,\"total_reads_processed\":6758,\"rejected_connections\":0,\"active_defrag_key_hits\":0,\"client_query_buffer_limit_disconn"
  ]
 },
 {
  "item_id": "elastic_indices",
  "kind": "exposure",
  "description": "An Elasticsearch server lists its data indices to anyone, without a login.",
  "evidence": [
   "indices: user,cdb,rest,api,rails,3.0,web,git,fpc,wp-json,webhook-test,service_transport,gitea,storage,connection,dsp,jeecg-boot,internal,apisix,read_me,rc,test,actuator,config,ajax-api,form,rds-data,webhook,auth,v1,v2,v3,goform,pritunl,solr,suite-auth,runners,cgi-bin,hybridity,service,plugin,admin,f",
   "indices: magento2_product_2_v4,top_queries-2026.10.23-59524,top_queries-2026.10.26-59527,magento2_product_3_v4,.plugins-ml-config,magento2_product_4_v4,top_queries-2026.10.25-59526,top_queries-2026.10.24-59525,magento2_product_1_v4"
  ]
 },
 {
  "item_id": "docker_registry_open",
  "kind": "exposure",
  "description": "A Docker image registry lists its stored images to anyone, without a login.",
  "evidence": [
   "[\"mp-projectdesigner-administration\",\"mp-projectdesigner-backend\"]",
   "[\"alpine\",\"alpine-tzdata\",\"common-service-api\",\"common-service-rpc\",\"common-service-schedule\",\"facebook-prophet-service\",\"file-service-api\",\"gohello\",\"logic-service-api\",\"logic-service-rpc\",\"my-nginx\",\"prophet-service-rpc\",\"purchase-service-api\",\"purchase-service-rpc\",\"python\",\"sale-service-api\",\"sa"
  ]
 },
 {
  "item_id": "ftp_anonymous",
  "kind": "exposure",
  "description": "An FTP file server accepted an anonymous login.",
  "evidence": [
   "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\n220-You are user number 1 of 150 allowed.\n220-Local time is now 07:04. Server port: 21.\n220-IPv6 connections are also welcome on this server.\n220 You will be disconnected after 15 minutes of inactivity.\r\n230 Anonymous user logged in\r\n214-",
   "220---------- Welcome to Pure-FTPd [privsep] [TLS] ----------\n220-You are user number 1 of 150 allowed.\n220-Local time is now 06:46. Server port: 21.\n220-IPv6 connections are also welcome on this server.\n220 You will be disconnected after 15 minutes of inactivity.\r\n230 Anonymous user logged in\r\n214-"
  ]
 },
 {
  "item_id": "smb_anonymous",
  "kind": "exposure",
  "description": "A Windows file-sharing (SMB) server lets anyone list at least one disk share without a login.",
  "evidence": [
   "[{\"temporary\":false,\"special\":false,\"type\":\"Disk\",\"name\":\"print$\",\"comments\":\"Printer Drivers\"},{\"temporary\":false,\"special\":false,\"type\":\"Disk\",\"name\":\"save\",\"comments\":\"Partage SMB\"},{\"temporary\":false,\"special\":false,\"type\":\"Disk\",\"name\":\"save1\",\"comments\":\"\"},{\"temporary\":false,\"special\":true,\"t",
   "[{\"temporary\":false,\"special\":false,\"type\":\"Disk\",\"name\":\"Samba_Share\",\"comments\":\"\"},{\"temporary\":false,\"special\":true,\"type\":\"IPC\",\"name\":\"IPC$\",\"comments\":\"IPC Service (Samba Server)\"}]"
  ]
 },
 {
  "item_id": "vnc_noauth",
  "kind": "exposure",
  "description": "A VNC remote-desktop server offers access with no password.",
  "evidence": [
   "{\"1\":\"None\"} | RFB 003.008\nAuthentication disabled\n\nVNC:\n  Protocol Version: 3.8\n  Security Types:\n    1: None\n",
   "{\"1\":\"None\"} | RFB 003.008\nAuthentication disabled\n\n\nSeaBIOS (version 1.16.3-debian-1.16.3-2)\nMachine UUID 1498235c-6650-477Z2-a3cc-f3f65e5c8Bcfc\n1IPXE (https:sszipxe.org) 01:"
  ]
 },
 {
  "item_id": "lantronix_password",
  "kind": "exposure",
  "description": "A Lantronix device server (a serial-to-network adapter) reveals its admin password in its reply.",
  "evidence": [
   "{\"version\":\"6.7.0.1\",\"mac\":\"00:20:4A:E4:60:32\",\"ip\":\"192.168.1.102\",\"gateway\":\"192.168.1.1\",\"password\":\"pacs\"}",
   "{\"type\":\"X9F\",\"version\":\"WVRC4+\",\"mac\":\"00:80:A3:46:3B:10\",\"ip\":\"24.148.100.74\",\"gateway\":\"24.148.100.73\",\"password\":\"sbti\"}"
  ]
 },
 {
  "item_id": "printer_no_password",
  "kind": "exposure",
  "description": "An HP printer's web admin page has no admin password set.",
  "evidence": [
   "{\"make_and_model\":\"ENVY 4520 All-in-One Printer series\",\"make_and_model_base\":\"ENVY 4520 All-in-One Printer series\",\"make_and_model_family\":\"ENVY 4520 series\",\"sku_identifier\":\"4527\",\"uuid\":\"1c852a4d-b800-1f08-abcd-a08cfdb67aeb\",\"serial_number\":\"TH65J3C18Q0660\",\"product_number\":\"J6U61B\",\"service_id\"",
   "{\"make_and_model\":\"HP Color LaserJet Pro M454dw\",\"make_and_model_base\":\"HP Color LaserJet Pro M454dw\",\"make_and_model_family\":\"HP Color LaserJet Pro M453-4\",\"sku_identifier\":\"M454dw\",\"uuid\":\"f49d2a6e-4365-539f-9581-f26b879b1ca2\",\"serial_number\":\"VNB3N00410\",\"product_number\":\"W1Y45A\",\"service_id\":\"32"
  ]
 },
 {
  "item_id": "ai_llm_open",
  "kind": "exposure",
  "description": "A self-hosted AI model server (Ollama, llama.cpp, LocalAI, ComfyUI or AnythingLLM) accepts requests without a login.",
  "evidence": [
   "{\"glm-5.3:cloud\":{\"model_info\":{\"general.parameter_count\":753329940480,\"general.architecture\":\"glm_dsa_moe\",\"glm_dsa_moe.context_length\":1048576,\"glm_dsa_moe.embedding_length\":0},\"thinking\":{\"default\":\"max\",\"values\":[\"low\",\"high\",\"max\"]},\"modified_at\":\"2026-08-28T08:00:00-07:00\",\"details\":{\"quantiza",
   "{\"models\":[{\"object\":\"model\",\"tags\":[],\"created\":1793016813,\"meta\":{\"vocabulary_type\":true,\"embedding_dimensions\":2560,\"max_context_length\":262144,\"vocabulary_size\":248320,\"ftype\":\"IQ1_M - 1.75 bpw\",\"total_parameters\":176943899520,\"n_ctx\":8192,\"model_size\":74527731200},\"owned_by\":\"llamacpp\",\"id\":\"/v"
  ]
 },
 {
  "item_id": "ics_protocol",
  "kind": "exposure",
  "description": "An industrial control system (Siemens S7, BACnet, EtherNet/IP, CODESYS, KNX, PCWorx, MELSEC or Modbus) answers control-protocol requests from the internet.",
  "evidence": [
   "{\"dst_tsap\":\"0x200\",\"src_tsap\":\"0x100\",\"identities\":{\"Basic Hardware\":{\"raw\":\"36455337203231312d31414534302d30584230200000000e2020\",\"value\":\"6ES7 211-1AE40-0XB0  v.0.14\"},\"Module\":{\"raw\":\"36455337203231312d31414534302d30584230200000000e2020\",\"value\":\"6ES7 211-1AE40-0XB0  v.0.14\"},\"Basic Firmware\":{\"",
   "[{\"uid\":0,\"response\":[[\"Slave ID Data\",\"Illegal Function (Error)\"],[\"Device Identification\",\"Illegal Function (Error)\"]]},{\"uid\":1,\"response\":[[\"Slave ID Data\",\"Illegal Function (Error)\"],[\"Device Identification\",\"Illegal Function (Error)\"]]},{\"uid\":255,\"response\":[[\"Slave ID Data\",\"Illegal Function"
  ]
 },
 {
  "item_id": "tag_ssh_bad_key",
  "kind": "exposure",
  "description": "An SSH server uses a host key that is publicly known (shipped as a default or leaked), so its connections can be impersonated or decrypted.",
  "evidence": [
   "ssh-bad-key | 1c:1e:29:43:d2:0c:c1:75:40:05:30:03:d4:02:d7:9b | SSH-2.0-dropbear_2017.75\nKey type: ssh-rsa\nKey: AAAAB3NzaC1yc2EAAAADAQABAAAAgwCW6ToMbteHdLBddvV/CP3Hk1tF2Av180UFvyyK17lpOIKe\nvtf+NWso/opmKKwePxAaGCz9cDWkJd2/Q1j",
   "ssh-bad-key | c2:a6:fb:9e:ce:e0:e4:84:61:88:0b:ec:05:e8:f4:aa | SSH-2.0-dropbear_0.46\nKey type: ssh-rsa\nKey: AAAAB3NzaC1yc2EAAAADAQABAAAAgwCCuYhaXf8RgI8tXtKZMCoCTcuC0VCNPjnII/3gee48KhD0\nuAs3NpwYzvKf08G/PDllpml++kb8YxdnT4wqQE"
  ]
 },
 {
  "item_id": "opts_vuln_tilde",
  "kind": "exposure",
  "description": "The scanner listed a vulnerability for this service as possible but unconfirmed, inferred from the software version.",
  "evidence": [
   "~CVE-2021-31206,~CVE-2021-34523,~CVE-2021-34473,~CVE-2021-31207 | Outlook | HTTP/1.1 200 OK\r\nCache-Control: no-cache, no-store\r\nContent-Type: text/html; charset=utf-8\r\nExpires: -1\r\nPragma: no-cach",
   "~CVE-2021-31206,~CVE-2021-34523,~CVE-2021-34473,~CVE-2021-31207 | \n   Exchange Admin Center\n   | HTTP/1.1 200 OK\r\nDate: Mon, 26 Oct 2026 12:08:15 GMT\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: 33985\r\nCon"
  ]
 },
 {
  "item_id": "atg_inventory",
  "kind": "exposure",
  "description": "A fuel-tank gauge (automatic tank gauge) answers inventory commands from the internet, showing tank contents and levels.",
  "evidence": [
   "\\nI20100\\nOCT 26, 2026  12:19 PM\\n\\nSUMMIT GAS & GO\\n5599 INTERSTATE PKWY\\nFRANKLIN, TN\\n\\nIN-TANK INVENTORY\\n\\nTANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP\\n  1  UNLEADED             8000      7986     2000    38.11     0.00    68.24\\n  2  PREMIUM              6240 ",
   "\\nI20100\\nOCT 26, 2026  12:06 PM\\n\\nREDWOOD GAS STOP\\n3050 FRONTAGE RD\\nFAIRVIEW, OR\\n\\nIN-TANK INVENTORY\\n\\nTANK PRODUCT             VOLUME TC VOLUME   ULLAGE   HEIGHT    WATER     TEMP\\n  1  DIESEL               5390      5374     5610    25.32     0.00    68.46\\n  2  PLUS                 2520    "
  ]
 },
 {
  "item_id": "rsync_noauth",
  "kind": "exposure",
  "description": "An rsync file-sync server lists its shared folders without a login.",
  "evidence": [
   "{\"tuncay\":\"/Tuncay\",\"alev\":\"/Alev\",\"sync\":\"/Bitenler\",\"hasan\":\"/Hasan\",\"nesibe\":\"/Nesibe\",\"ydek\":\"/Tuncay\",\"duru\":\"/DANISMANLIK\",\"atila\":\"/Atilla\",\"olcay\":\"/Olcay\"}",
   "{\"documentos\":\"RSYNC NAS Oficina\"}"
  ]
 },
 {
  "item_id": "ipmi_exposed",
  "kind": "exposure",
  "description": "A server's out-of-band management controller (IPMI) is reachable from the internet.",
  "evidence": [
   "{\"version\":\"IPMI-2.0\",\"user_auth\":[\"password\",\"md5\",\"md2\"],\"password_auth\":[\"auth_msg\",\"auth_user\",\"non_null_user\"],\"level\":[\"1.5\",\"2.0\"],\"oemid\":21317}",
   "{\"version\":\"IPMI-2.0\",\"password_auth\":[\"auth_user\",\"non_null_user\"],\"level\":[\"2.0\"]}"
  ]
 },
 {
  "item_id": "esxi_exposed",
  "kind": "exposure",
  "description": "A VMware ESXi or vCenter virtualisation management service is reachable from the internet.",
  "evidence": [
   "VMware ESXi 6.0.0 build-3620759",
   "VMware ESXi 6.0.0 build-3380124"
  ]
 },
 {
  "item_id": "ntp_monlist",
  "kind": "exposure",
  "description": "An NTP time server answers the 'monlist' command, which returns a list of its recent clients and a reply much larger than the request.",
  "evidence": [
   "{\"connections\":[\"224.224.212.220:46446\",\"34.140.48.2:36710\",\"35.187.70.136:63095\"],\"more\":false}",
   "{\"connections\":[\"224.24.93.173:34086\",\"44.30.62.52:123\",\"208.88.66.8:123\",\"46.250.253.227:123\",\"151.243.11.231:43942\",\"45.198.224.252:53662\"],\"more\":true}"
  ]
 },
 {
  "item_id": "dns_open_resolver",
  "kind": "exposure",
  "description": "A DNS server answers recursive lookups for anyone on the internet.",
  "evidence": [
   "{\"resolver_hostname\":null,\"recursive\":true,\"resolver_id\":null,\"software\":null} | \nRecursion: enabled",
   "{\"resolver_hostname\":null,\"recursive\":true,\"resolver_id\":\"min5-dns2-02.inet.centurylink.net\",\"software\":null} | \nRecursion: enabled\nResolver ID: min5-dns2-02.inet.centurylink.net"
  ]
 },
 {
  "item_id": "snmp_v1_v2",
  "kind": "exposure",
  "description": "An SNMP v1 or v2 network-management service returned the device's description or name to a community string (a shared password, often a default).",
  "evidence": [
   "{\"uptime\":\"331014900\",\"description\":\"RouterOS CCR1036-12G-4S 7.24.4 (stable)\",\"service\":\"78\",\"versions\":[1,3],\"name\":\"E4:8D:8C:01:A8:28\",\"engineid_format\":\"text\",\"engine_boots\":0,\"engineid_data\":\"80003a8c04\",\"enterprise\":14988,\"objectid\":\"1.3.6.1.4.1.14988.1\",\"engine_time\":\"0:00:00\",\"enterprise_name",
   "{\"uptime\":\"7975279\",\"description\":\"SD5840-01 Advanced Digital Broadcast SA 6.7.0.0053\",\"service\":\"74\",\"versions\":[1,3],\"name\":\"ge-cpe-ori59-1\",\"ordescr\":\"View-based Access Control Model for SNMP.\",\"contact\":\"root@localhost\",\"oruptime\":\"0\",\"engine_boots\":1,\"engineid_data\":\"80001f8880957ae22c41385862\""
  ]
 },
 {
  "item_id": "rdp_exposed",
  "kind": "exposure",
  "description": "A Windows Remote Desktop (RDP) login is reachable from the internet.",
  "evidence": [
   "Remote Desktop Protocol | 10.0.17763 | {\"levels\":[],\"methods\":[],\"protocols\":[\"Hybrid (TLS + CredSSP EX) Security\",\"Hybrid (TLS + CredSSP) Security\"]} | Remote Desktop Protocol\n\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02\\x1f\\x08\\x00\\x02\\x00\\x00\\x00\nRemote Desktop Protocol NTLM Info:\n  OS: Windows ",
   "Remote Desktop Protocol | 10.0.20348 | {\"rdp_version\":\"10.9\",\"levels\":[],\"methods\":[],\"protocols\":[\"Hybrid (TLS + CredSSP EX) Security\",\"TLS 1.0, 1.1 or 1.2 Security\",\"Hybrid (TLS + CredSSP) Security\"]} | Remote Desktop Protocol\n\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02\\x1f\\x08\\x00\\x02\\x00\\x00\\x"
  ]
 },
 {
  "item_id": "rdp_standard_security",
  "kind": "exposure",
  "description": "A Windows Remote Desktop server accepts its legacy 'Standard RDP Security' mode instead of requiring TLS with network-level authentication.",
  "evidence": [
   "{\"rdp_version\":\"5.0-8.1\",\"levels\":[\"Client Compatible\"],\"methods\":[\"56 Bit\",\"40 Bit\",\"FIPS\",\"128 Bit\"],\"protocols\":[\"Standard RDP Security\",\"Hybrid (TLS + CredSSP EX) Security\",\"TLS 1.0, 1.1 or 1.2 Security\",\"Hybrid (TLS + CredSSP) Security\"]}",
   "{\"rdp_version\":\"5.0-8.1\",\"levels\":[\"High\"],\"methods\":[\"128 Bit\"],\"protocols\":[\"Standard RDP Security\",\"TLS 1.0, 1.1 or 1.2 Security\"]}"
  ]
 },
 {
  "item_id": "smb_v1",
  "kind": "exposure",
  "description": "A Windows file-sharing server speaks SMB version 1, the original protocol version.",
  "evidence": [
   "SMBv1 | Windows Server 2012 R2 Datacenter 6.3 | SMB Status:\n  Authentication: enabled\n  SMB Version: 1\n  OS: Windows Server 2012 R2 Datacenter 9600\n  Software: Windows Server 2012 R2 Datacenter 6.3\n  Capabilities: extended-security, infolevel-passt",
   "SMBv1 | Windows Server 2012 R2 Standard 6.3 | SMB Status:\n  Authentication: enabled\n  SMB Version: 1\n  OS: Windows Server 2012 R2 Standard 9600\n  Software: Windows Server 2012 R2 Standard 6.3\n  Capabilities: extended-security, infolevel-passthru,"
  ]
 },
 {
  "item_id": "telnet_object",
  "kind": "exposure",
  "description": "A Telnet service (an unencrypted remote login) is reachable from the internet.",
  "evidence": [
   "\r\nWarning: Telnet is not a secure protocol, and it is recommended to use Stelnet.\r\n\r\nLogin authentication\r\n\r\n\r\nUsername: | {\"will\":[\"ECHO\",\"SGA\"],\"do\":[\"TTYPE\",\"NAWS\"],\"dont\":[],\"wont\":[]}",
   "tc login:  | {\"will\":[\"ECHO\",\"SGA\"],\"do\":[\"ECHO\",\"LFLOW\"],\"dont\":[],\"wont\":[]}"
  ]
 },
 {
  "item_id": "node_exporter_open",
  "kind": "exposure",
  "description": "A Prometheus node exporter publishes the machine's system metrics to anyone.",
  "evidence": [
   "{\"domainname\":\"(none)\",\"machine\":\"x86_64\",\"nodename\":\"yearenddeals.net\",\"release\":\"5.14.0-427.13.1.el9_4.x86_64\",\"sysname\":\"Linux\",\"version\":\"#1 SMP PREEMPT_DYNAMIC Wed May 1 19:11:28 UTC 2024\"}",
   "{\"domainname\":\"(none)\",\"machine\":\"x86_64\",\"nodename\":\"v2.send.adxabsalt00.com\",\"release\":\"6.8.0-139-generic\",\"sysname\":\"Linux\",\"version\":\"#139-Ubuntu SMP PREEMPT_DYNAMIC Sat Aug  1 03:52:05 UTC 2026\"}"
  ]
 },
 {
  "item_id": "http_dir_listing",
  "kind": "exposure",
  "description": "A web server shows a listing of the files in a directory.",
  "evidence": [
   "Index of / | {\"extensions\":[],\"data\":{\"cgi-bin/\":{\"type\":\"folder\"}},\"hash\":-2117260003} | <!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\"> <html> <head> <title>Index of /</title> </head> <body> <h1>Index of /</h1> <table> <tr><th valign=\"top\">&nbsp;</th><th>",
   "Index of / | {\"extensions\":[\"jpg\",\"php\",\"txt\",\"xml\"],\"data\":{\"random3500x3500.jpg\":{\"timestamp\":\"Fri, 29 Dec 2017 10:16:24 GMT\",\"type\":\"file\",\"size\":24262167},\"random350x350.jpg\":{\"timestamp\":\"Fri, 29 Dec 2017 10:16:24 GMT\",\"type\":\"file\",\"size\":245388},\"random1500x1500.jpg\":{\"timestamp\":\"Fri, 29 Dec"
  ]
 },
 {
  "item_id": "tag_database",
  "kind": "exposure",
  "description": "A database server (such as MySQL, PostgreSQL or SQL Server) is reachable from the internet and answered the scanner rather than refusing it.",
  "evidence": [
   "tcp,influxdb | InfluxDB | HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nX-Influxdb-Build: OSS\r\nX-Influxdb-Version: 1.6.7~rc0\r\nDate: Mon, 26 Oct 2026 12:02:29 GMT\r\nContent-Length: 19\r\n\r\n\nInfluxDB",
   "tcp,mysql | MariaDB | MariaDB:\n  Protocol Version: 10\n  Version: 10.1.48-MariaDB\n  Capabilities: 63487\n  Server Language: 9\n  Server Status: 2\n  Extended Server Capabilities: 41023\n  Authentication Plugin: mysql_native_password"
  ]
 },
 {
  "item_id": "tag_medical",
  "kind": "exposure",
  "description": "A medical imaging system (DICOM) accepted a connection from the internet.",
  "evidence": [
   "medical | DICOM Server Response\n\\x02\\x00\\x00\\x00\\x00\\xb8\\x00\\x01\\x00\\x00ANY-SCP         FINDSCU         \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x",
   "medical | DICOM Server Response\n\\x02\\x00\\x00\\x00\\x00\\xaf\\x00\\x01\\x00\\x00ANY-SCP         FINDSCU         \\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x"
  ]
 },
 {
  "item_id": "tls_sslv2_sslv3",
  "kind": "exposure",
  "description": "The service still accepts the obsolete SSLv2 or SSLv3 encryption protocols.",
  "evidence": [
   "-SSLv2,SSLv3,TLSv1,TLSv1.1,-TLSv1.2,-TLSv1.3 | AES256-SHA",
   "-SSLv2,SSLv3,TLSv1,TLSv1.1,TLSv1.2,-TLSv1.3 | AES256-SHA"
  ]
 },
 {
  "item_id": "tls_weak_key",
  "kind": "exposure",
  "description": "The service's certificate uses an RSA key under 2048 bits or an MD5 signature.",
  "evidence": [
   "rsa 1024 | sha256WithRSAEncryption | {\"C\":\"CN\",\"CN\":\"103.60.148.26\",\"L\":\"Dongguan\",\"O\":\"BT-PANEL\",\"ST\":\"Guangdong\",\"emailAddress\":\"admin@bt.cn\",\"OU\":\"BT\"}",
   "rsa 1024 | sha1WithRSAEncryption | {\"C\":\"CH\",\"CN\":\"PON\",\"L\":\"WU\",\"O\":\"FH\",\"ST\":\"HU\",\"emailAddress\":\"PON@FIBERHOME.COM.CN\",\"OU\":\"SF\"}"
  ]
 },
 {
  "item_id": "tag_eol_os",
  "kind": "exposure",
  "description": "The scanner identified the operating system as end-of-life: it no longer gets security updates.",
  "evidence": [
   "eol-os | Windows (build 6.3.9600) | Remote Desktop Protocol\n\\x03\\x00\\x00\\x13\\x0e\\xd0\\x00\\x00\\x124\\x00\\x02\\x0f\\x08\\x00\\x02\\x00\\x00\\x00\nRemote Desktop Protocol NTLM Info:\n  OS: Windows 8.1/Windows S",
   "eol-os | Rocky Linux 9.8 (Blue Onyx) (Linux 5.14.0-427.13.1.el9_4.x86_64) | HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n400 Bad Request\nPrometheus Node Exporter:\n  node_exporter_build_info:\n  "
  ]
 },
 {
  "item_id": "CVE-2013-1391",
  "kind": "vulnerability",
  "description": "Authentication bypass vulnerability in the the web interface in Hunt CCTV, Capture CCTV, Hachi CCTV, NoVus CCTV, and Well-Vision Inc DVR systems allows a remote attacker to retrieve the device configuration.",
  "evidence": []
 },
 {
  "item_id": "CVE-2013-1899",
  "kind": "vulnerability",
  "description": "Argument injection vulnerability in PostgreSQL 9.2.x before 9.2.4, 9.1.x before 9.1.9, and 9.0.x before 9.0.13 allows remote attackers to cause a denial of service (file corruption), and allows remote authenticated users to modify configuration settings and execute arbitrary code, via a connection request using a database name that begins with a \"-\" (hyphen).",
  "evidence": []
 },
 {
  "item_id": "CVE-2014-0160",
  "kind": "vulnerability",
  "description": "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, as demonstrated by reading private keys, related to d1_both.c and t1_lib.c, aka the Heartbleed bug.",
  "evidence": []
 },
 {
  "item_id": "CVE-2015-0204",
  "kind": "vulnerability",
  "description": "The ssl3_get_key_exchange function in s3_clnt.c in OpenSSL before 0.9.8zd, 1.0.0 before 1.0.0p, and 1.0.1 before 1.0.1k allows remote SSL servers to conduct RSA-to-EXPORT_RSA downgrade attacks and facilitate brute-force decryption by offering a weak ephemeral RSA key in a noncompliant role, related to the \"FREAK\" issue. NOTE: the scope of this CVE is only client code based on OpenSSL, not EXPORT_RSA issues associated with servers or other TLS implementations.",
  "evidence": []
 },
 {
  "item_id": "CVE-2015-1635",
  "kind": "vulnerability",
  "description": "HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka \"HTTP.sys Remote Code Execution Vulnerability.\"",
  "evidence": []
 },
 {
  "item_id": "CVE-2015-2080",
  "kind": "vulnerability",
  "description": "The exception handling code in Eclipse Jetty before 9.2.9.v20150224 allows remote attackers to obtain sensitive information from process memory via illegal characters in an HTTP header, aka JetLeak.",
  "evidence": []
 },
 {
  "item_id": "CVE-2015-4000",
  "kind": "vulnerability",
  "description": "The TLS protocol 1.2 and earlier, when a DHE_EXPORT ciphersuite is enabled on a server but not on a client, does not properly convey a DHE_EXPORT choice, which allows man-in-the-middle attackers to conduct cipher-downgrade attacks by rewriting a ClientHello with DHE replaced by DHE_EXPORT and then rewriting a ServerHello with DHE_EXPORT replaced by DHE, aka the \"Logjam\" issue.",
  "evidence": []
 },
 {
  "item_id": "CVE-2017-7269",
  "kind": "vulnerability",
  "description": "Buffer overflow in the ScStoragePathFromUrl function in the WebDAV service in Internet Information Services (IIS) 6.0 in Microsoft Windows Server 2003 R2 allows remote attackers to execute arbitrary code via a long header beginning with \"If: <http://\" in a PROPFIND request.",
  "evidence": []
 },
 {
  "item_id": "CVE-2018-18441",
  "kind": "vulnerability",
  "description": "D-Link DCS series Wi-Fi cameras expose sensitive information regarding the device configuration. The affected devices include many of DCS series, such as: DCS-936L, DCS-942L, DCS-8000LH, DCS-942LB1, DCS-5222L, DCS-825L, DCS-2630L, DCS-820L, DCS-855L, DCS-2121, DCS-5222LB1, DCS-5020L, and many more. There are many affected firmware versions starting from 1.00 and above. The configuration file can be accessed remotely through: <Camera-IP>/common/info.cgi, with no authentication. The configuration file include the following fields: model, product, brand, version, build, hw_version, nipca version, device name, location, MAC address, IP address, gateway IP address, wireless status, input/output settings, speaker, and sensor settings.",
  "evidence": []
 },
 {
  "item_id": "CVE-2019-0708",
  "kind": "vulnerability",
  "description": "A remote code execution vulnerability exists in Remote Desktop Services formerly known as Terminal Services when an unauthenticated attacker connects to the target system using RDP and sends specially crafted requests, aka 'Remote Desktop Services Remote Code Execution Vulnerability'.",
  "evidence": []
 },
 {
  "item_id": "CVE-2019-11510",
  "kind": "vulnerability",
  "description": "In Pulse Secure Pulse Connect Secure (PCS) 8.2 before 8.2R12.1, 8.3 before 8.3R7.1, and 9.0 before 9.0R3.4, an unauthenticated remote attacker can send a specially crafted URI to perform an arbitrary file reading vulnerability .",
  "evidence": []
 },
 {
  "item_id": "CVE-2019-1652",
  "kind": "vulnerability",
  "description": "A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an authenticated, remote attacker with administrative privileges on an affected device to execute arbitrary commands. The vulnerability is due to improper validation of user-supplied input. An attacker could exploit this vulnerability by sending malicious HTTP POST requests to the web-based management interface of an affected device. A successful exploit could allow the attacker to execute arbitrary commands on the underlying Linux shell as root. Cisco has released firmware updates that address this vulnerability.",
  "evidence": []
 },
 {
  "item_id": "CVE-2019-1653",
  "kind": "vulnerability",
  "description": "A vulnerability in the web-based management interface of Cisco Small Business RV320 and RV325 Dual Gigabit WAN VPN Routers could allow an unauthenticated, remote attacker to retrieve sensitive information. The vulnerability is due to improper access controls for URLs. An attacker could exploit this vulnerability by connecting to an affected device via HTTP or HTTPS and requesting specific URLs. A successful exploit could allow the attacker to download the router configuration or detailed diagnostic information. Cisco has released firmware updates that address this vulnerability.",
  "evidence": []
 },
 {
  "item_id": "CVE-2020-0796",
  "kind": "vulnerability",
  "description": "A remote code execution vulnerability exists in the way that the Microsoft Server Message Block 3.1.1 (SMBv3) protocol handles certain requests, aka 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability'.",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-26855",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-26857",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-26858",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-27065",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-31206",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-31207",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Security Feature Bypass Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-34473",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Remote Code Execution Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-34523",
  "kind": "vulnerability",
  "description": "Microsoft Exchange Server Elevation of Privilege Vulnerability",
  "evidence": []
 },
 {
  "item_id": "CVE-2021-43798",
  "kind": "vulnerability",
  "description": "Grafana is an open-source platform for monitoring and observability. Grafana versions 8.0.0-beta1 through 8.3.0 (except for patched versions) iss vulnerable to directory traversal, allowing access to local files. The vulnerable URL path is: `<grafana_host_url>/public/plugins//`, where is the plugin ID for any installed plugin. At no time has Grafana Cloud been vulnerable. Users are advised to upgrade to patched versions 8.0.7, 8.1.8, 8.2.7, or 8.3.1. The GitHub Security Advisory contains more information about vulnerable URL paths, mitigation, and the disclosure timeline.",
  "evidence": []
 },
 {
  "item_id": "CVE-2022-32548",
  "kind": "vulnerability",
  "description": "An issue was discovered on certain DrayTek Vigor routers before July 2022 such as the Vigor3910 before 4.3.1.1. /cgi-bin/wlogin.cgi has a buffer overflow via the username or password to the aa or ab field.",
  "evidence": []
 },
 {
  "item_id": "CVE-2023-22496",
  "kind": "vulnerability",
  "description": "Netdata is an open source option for real-time infrastructure monitoring and troubleshooting. An attacker with the ability to establish a streaming connection can execute arbitrary commands on the targeted Netdata agent. When an alert is triggered, the function `health_alarm_execute` is called. This function performs different checks and then enqueues a command by calling `spawn_enq_cmd`. This command is populated with several arguments that are not sanitized. One of them is the `registry_hostname` of the node for which the alert is raised. By providing a specially crafted `registry_hostname` as part of the health data that is streamed to a Netdata (parent) agent, an attacker can execute arbitrary commands at the remote host as a side-effect of the raised alert. Note that the commands are executed as the user running the Netdata Agent. This user is usually named `netdata`. The ability to run arbitrary commands may allow an attacker to escalate privileges by escalating other vulnerabilities in the system, as that user. The problem has been fixed in: Netdata agent v1.37 (stable) and Netdata agent v1.36.0-409 (nightly). As a workaround, streaming is not enabled by default. If you have previously enabled this, it can be disabled. Limiting access to the port on the recipient Agent to trusted child connections may mitigate the impact of this vulnerability.",
  "evidence": []
 },
 {
  "item_id": "CVE-2023-22497",
  "kind": "vulnerability",
  "description": "Netdata is an open source option for real-time infrastructure monitoring and troubleshooting. Each Netdata Agent has an automatically generated MACHINE GUID. It is generated when the agent first starts and it is saved to disk, so that it will persist across restarts and reboots. Anyone who has access to a Netdata Agent has access to its MACHINE_GUID. Streaming is a feature that allows a Netdata Agent to act as parent for other Netdata Agents (children), offloading children from various functions (increased data retention, ML, health monitoring, etc) that can now be handled by the parent Agent. Configuration is done via `stream.conf`. On the parent side, users configure in `stream.conf` an API key (any random UUID can do) to provide common configuration for all children using this API key and per MACHINE GUID configuration to customize the configuration for each child. The way this was implemented, allowed an attacker to use a valid MACHINE_GUID as an API key. This affects all users who expose their Netdata Agents (children) to non-trusted users and they also expose to the same users Netdata Agent parents that aggregate data from all these children. The problem has been fixed in: Netdata agent v1.37 (stable) and Netdata agent v1.36.0-409 (nightly). As a workaround, do not enable streaming by default. If you have previously enabled this, it can be disabled. Limiting access to the port on the recipient Agent to trusted child connections may mitigate the impact of this vulnerability.",
  "evidence": []
 },
 {
  "item_id": "CVE-2023-23333",
  "kind": "vulnerability",
  "description": "There is a command injection vulnerability in SolarView Compact through 6.00, attackers can execute commands by bypassing internal restrictions through downloader.php.",
  "evidence": []
 },
 {
  "item_id": "CVE-2023-33193",
  "kind": "vulnerability",
  "description": "Emby Server is a user-installable home media server which stores and organizes a user's media files of virtually any format and makes them available for viewing at home and abroad on a broad range of client devices. This vulnerability may allow administrative access to an Emby Server system, depending on certain user account settings. By spoofing certain headers which are intended for interoperation with reverse proxy servers, it may be possible to affect the local/non-local network determination to allow logging in without password or to view a list of user accounts which may have no password configured. Impacted are all Emby Server system which are publicly accessible and where the administrator hasn't tightened the account login configuration for administrative users. This issue has been patched in Emby Server Beta version 4.8.31 and Emby Server version 4.7.12.",
  "evidence": []
 },
 {
  "item_id": "CVE-2023-33246",
  "kind": "vulnerability",
  "description": "For RocketMQ versions 5.1.0 and below, under certain conditions, there is a risk of remote command execution. Several components of RocketMQ, including NameServer, Broker, and Controller, are leaked on the extranet and lack permission verification, an attacker can exploit this vulnerability by using the update configuration function to execute commands as the system users that RocketMQ is running as. Additionally, an attacker can achieve the same effect by forging the RocketMQ protocol content. To prevent these attacks, users are recommended to upgrade to version 5.1.1 or above for using RocketMQ 5.x or 4.9.6 or above for using RocketMQ 4.x .",
  "evidence": []
 },
 {
  "item_id": "CVE-2023-48702",
  "kind": "vulnerability",
  "description": "Jellyfin is a system for managing and streaming media. Prior to version 10.8.13, the `/System/MediaEncoder/Path` endpoint executes an arbitrary file using `ProcessStartInfo` via the `ValidateVersion` function. A malicious administrator can setup a network share and supply a UNC path to `/System/MediaEncoder/Path` which points to an executable on the network share, causing Jellyfin server to run the executable in the local context. The endpoint was removed in version 10.8.13.",
  "evidence": []
 },
 {
  "item_id": "CVE-2024-23897",
  "kind": "vulnerability",
  "description": "Jenkins 2.441 and earlier, LTS 2.426.2 and earlier does not disable a feature of its CLI command parser that replaces an '@' character followed by a file path in an argument with the file's contents, allowing unauthenticated attackers to read arbitrary files on the Jenkins controller file system.",
  "evidence": []
 },
 {
  "item_id": "CVE-2025-5777",
  "kind": "vulnerability",
  "description": "Insufficient input validation leading to memory overread when the NetScaler is configured as a Gateway (VPN virtual server, ICA Proxy, CVPN, RDP Proxy) OR AAA virtual server",
  "evidence": []
 },
 {
  "item_id": "MS15-034",
  "kind": "vulnerability",
  "description": "HTTP.sys in Microsoft Windows 7 SP1, Windows Server 2008 R2 SP1, Windows 8, Windows 8.1, and Windows Server 2012 Gold and R2 allows remote attackers to execute arbitrary code via crafted HTTP requests, aka \"HTTP.sys Remote Code Execution Vulnerability.\"",
  "evidence": []
 },
 {
  "item_id": "MS17-010",
  "kind": "vulnerability",
  "description": "This security update resolves vulnerabilities in Microsoft Windows. The most severe of the vulnerabilities could allow remote code execution if an attacker sends specially crafted messages to a Microsoft Server Message Block 1.0 (SMBv1) server. This security update is rated Critical for all supported releases of Microsoft Windows.",
  "evidence": []
 }
]
