package services

import (
	"encoding/xml"
	"os"
	"strconv"

	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

type NmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []NmapHost `xml:"host"`
}

type NmapHost struct {
	Addresses []NmapAddress  `xml:"address"`
	Hostnames []NmapHostname `xml:"hostnames>hostname"`
	Status    NmapStatus     `xml:"status"`
	OS        *NmapOS        `xml:"os"`
	Ports     []NmapPort     `xml:"ports>port"`
}

type NmapAddress struct {
	Addr string `xml:"addr,attr"`
}

type NmapHostname struct {
	Name string `xml:"name,attr"`
}

type NmapStatus struct {
	State string `xml:"state,attr"`
}

type NmapOS struct {
	OSMatches []NmapOSMatch `xml:"osmatch"`
}

type NmapOSMatch struct {
	Name string `xml:"name,attr"`
}

type NmapPort struct {
	PortID   string        `xml:"portid,attr"`
	Protocol string        `xml:"protocol,attr"`
	State    NmapPortState `xml:"state"`
	Service  *NmapService  `xml:"service"`
}

type NmapPortState struct {
	State string `xml:"state,attr"`
}

type NmapService struct {
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
}

func CreateReportFromXML(runID uint, xmlPath, normalPath string) error {
	data, err := os.ReadFile(xmlPath)
	if err != nil {
		return err
	}

	var run NmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return err
	}

	report := models.ScanReport{
		ScanRunID:        runID,
		XMLReportPath:    xmlPath,
		NormalReportPath: normalPath,
	}
	if err := db.DB.Create(&report).Error; err != nil {
		return err
	}

	// nmap emits one <host> per target spec, so "127.0.0.1" and "localhost"
	// both produce a host block for the same IP. Merge them so the report has
	// one row per address with the union of its ports.
	hostByIP := map[string]*models.HostFinding{}
	seenPort := map[string]bool{}
	var order []string
	for _, h := range run.Hosts {
		ip := ""
		if len(h.Addresses) > 0 {
			ip = h.Addresses[0].Addr
		}
		host, exists := hostByIP[ip]
		if !exists {
			host = &models.HostFinding{ReportID: report.ID, IPAddress: ip, Status: h.Status.State}
			hostByIP[ip] = host
			order = append(order, ip)
		}
		if h.Status.State == "up" {
			host.Status = "up"
		}
		if host.Hostname == "" && len(h.Hostnames) > 0 {
			host.Hostname = h.Hostnames[0].Name
		}
		if host.OSInfo == "" && h.OS != nil && len(h.OS.OSMatches) > 0 {
			host.OSInfo = h.OS.OSMatches[0].Name
		}
		for _, p := range h.Ports {
			key := ip + "|" + p.PortID + "/" + p.Protocol
			if seenPort[key] {
				continue
			}
			seenPort[key] = true
			portNum, _ := strconv.Atoi(p.PortID)
			port := models.PortFinding{PortNumber: portNum, Protocol: p.Protocol, State: p.State.State}
			if p.Service != nil {
				port.Service = p.Service.Name
				port.Version = p.Service.Version
			}
			host.Ports = append(host.Ports, port)
		}
	}

	for _, ip := range order {
		host := hostByIP[ip]
		if err := db.DB.Create(host).Error; err != nil {
			return err
		}
	}

	return nil
}
