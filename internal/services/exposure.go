package services

import (
	"strconv"
	"strings"
)

// Notable describes why an open port deserves attention. Severity is a coarse
// heuristic ("high" for remote-admin, database, file-sharing and ICS services
// that should rarely be reachable from a scanner; "medium" for services that
// are normal but worth an inventory check). It is not a vulnerability rating.
type Notable struct {
	Label    string `json:"label"`
	Severity string `json:"severity"`
}

var notableByPort = map[string]Notable{
	"21/tcp":    {"FTP (cleartext)", "high"},
	"23/tcp":    {"Telnet (cleartext)", "high"},
	"69/udp":    {"TFTP", "high"},
	"111/tcp":   {"RPC portmapper", "high"},
	"135/tcp":   {"MS RPC", "high"},
	"139/tcp":   {"NetBIOS", "high"},
	"161/udp":   {"SNMP", "high"},
	"445/tcp":   {"SMB", "high"},
	"512/tcp":   {"rexec", "high"},
	"513/tcp":   {"rlogin", "high"},
	"514/tcp":   {"rsh", "high"},
	"1433/tcp":  {"MS SQL", "high"},
	"1521/tcp":  {"Oracle DB", "high"},
	"2049/tcp":  {"NFS", "high"},
	"2375/tcp":  {"Docker API (unencrypted)", "high"},
	"2376/tcp":  {"Docker API", "high"},
	"3306/tcp":  {"MySQL", "high"},
	"3389/tcp":  {"RDP", "high"},
	"5432/tcp":  {"PostgreSQL", "high"},
	"5900/tcp":  {"VNC", "high"},
	"5901/tcp":  {"VNC", "high"},
	"5985/tcp":  {"WinRM (HTTP)", "high"},
	"5986/tcp":  {"WinRM (HTTPS)", "high"},
	"6379/tcp":  {"Redis", "high"},
	"9200/tcp":  {"Elasticsearch", "high"},
	"11211/tcp": {"Memcached", "high"},
	"27017/tcp": {"MongoDB", "high"},
	"502/tcp":   {"Modbus (ICS)", "high"},
	"102/tcp":   {"Siemens S7 (ICS)", "high"},
	"20000/tcp": {"DNP3 (ICS)", "high"},
	"44818/tcp": {"EtherNet/IP (ICS)", "high"},
	"22/tcp":    {"SSH", "medium"},
	"25/tcp":    {"SMTP", "medium"},
	"88/tcp":    {"Kerberos", "medium"},
	"110/tcp":   {"POP3", "medium"},
	"143/tcp":   {"IMAP", "medium"},
	"389/tcp":   {"LDAP", "medium"},
	"636/tcp":   {"LDAPS", "medium"},
	"1883/tcp":  {"MQTT", "medium"},
	"3000/tcp":  {"Dev web server", "medium"},
	"5000/tcp":  {"Dev web server", "medium"},
	"5601/tcp":  {"Kibana", "medium"},
	"8000/tcp":  {"Alt HTTP", "medium"},
	"8080/tcp":  {"Alt HTTP", "medium"},
	"8443/tcp":  {"Alt HTTPS", "medium"},
	"8888/tcp":  {"Jupyter / alt HTTP", "medium"},
	"9090/tcp":  {"Admin console", "medium"},
	"10000/tcp": {"Webmin", "medium"},
}

var notableByService = map[string]Notable{
	"telnet": {"Telnet (cleartext)", "high"}, "ftp": {"FTP (cleartext)", "high"},
	"ms-wbt-server": {"RDP", "high"}, "rdp": {"RDP", "high"}, "vnc": {"VNC", "high"},
	"microsoft-ds": {"SMB", "high"}, "netbios-ssn": {"NetBIOS", "high"}, "smb": {"SMB", "high"},
	"mysql": {"MySQL", "high"}, "postgresql": {"PostgreSQL", "high"}, "redis": {"Redis", "high"},
	"mongodb": {"MongoDB", "high"}, "memcache": {"Memcached", "high"}, "memcached": {"Memcached", "high"},
	"ms-sql-s": {"MS SQL", "high"}, "oracle": {"Oracle DB", "high"}, "oracle-tns": {"Oracle DB", "high"},
	"docker": {"Docker API", "high"}, "snmp": {"SNMP", "high"}, "tftp": {"TFTP", "high"},
	"nfs": {"NFS", "high"}, "rpcbind": {"RPC portmapper", "high"}, "wsman": {"WinRM", "high"},
	"elasticsearch": {"Elasticsearch", "high"}, "modbus": {"Modbus (ICS)", "high"},
	"ssh": {"SSH", "medium"}, "smtp": {"SMTP", "medium"}, "ldap": {"LDAP", "medium"},
	"imap": {"IMAP", "medium"}, "pop3": {"POP3", "medium"}, "mqtt": {"MQTT", "medium"},
	"kerberos-sec": {"Kerberos", "medium"},
}

// NotableFor returns the notable classification for an open port, if any.
func NotableFor(port int, protocol, service string) (Notable, bool) {
	key := strings.ToLower(strings.TrimSpace(protocol))
	if n, ok := notableByPort[strconv.Itoa(port)+"/"+key]; ok {
		return n, true
	}
	if n, ok := notableByService[strings.ToLower(strings.TrimSpace(service))]; ok {
		return n, true
	}
	return Notable{}, false
}
