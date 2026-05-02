package services

import (
	"encoding/xml"
	"os"
	"strconv"

	"nmapwebui/internal/db"
	"nmapwebui/internal/models"
)

type NmapRun struct {
	XMLName xml.Name    `xml:"nmaprun"`
	Hosts   []NmapHost  `xml:"host"`
}

type NmapHost struct {
	Addresses   []NmapAddress   `xml:"address"`
	Hostnames   []NmapHostname  `xml:"hostnames>hostname"`
	Status      NmapStatus      `xml:"status"`
	OS          *NmapOS         `xml:"os"`
	Ports       []NmapPort      `xml:"ports>port"`
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
	PortID    string        `xml:"portid,attr"`
	Protocol  string        `xml:"protocol,attr"`
	State     NmapPortState `xml:"state"`
	Service   *NmapService  `xml:"service"`
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

	for _, h := range run.Hosts {
		host := models.HostFinding{
			ReportID: report.ID,
			Status:   h.Status.State,
		}
		if len(h.Addresses) > 0 {
			host.IPAddress = h.Addresses[0].Addr
		}
		if len(h.Hostnames) > 0 {
			host.Hostname = h.Hostnames[0].Name
		}
		if h.OS != nil && len(h.OS.OSMatches) > 0 {
			host.OSInfo = h.OS.OSMatches[0].Name
		}
		if err := db.DB.Create(&host).Error; err != nil {
			return err
		}

		for _, p := range h.Ports {
			portNum, _ := strconv.Atoi(p.PortID)
			port := models.PortFinding{
				HostID:     host.ID,
				PortNumber: portNum,
				Protocol:   p.Protocol,
				State:      p.State.State,
			}
			if p.Service != nil {
				port.Service = p.Service.Name
				port.Version = p.Service.Version
			}
			if err := db.DB.Create(&port).Error; err != nil {
				return err
			}
		}
	}

	return nil
}
