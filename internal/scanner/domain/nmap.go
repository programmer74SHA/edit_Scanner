package domain

import (
	"encoding/xml"
)

// NmapRun represents the root element of Nmap XML output
type NmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []Host   `xml:"host"`
}

// Host represents a host in Nmap XML output
type Host struct {
	XMLName   xml.Name  `xml:"host"`
	Status    Status    `xml:"status"`
	Addresses []Address `xml:"address"`
	Hostnames struct {
		Hostname []struct {
			Name string `xml:"name,attr"`
			Type string `xml:"type,attr"`
		} `xml:"hostname"`
	} `xml:"hostnames"`
	Ports struct {
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   int    `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name    string `xml:"name,attr"`
				Product string `xml:"product,attr,omitempty"`
				Version string `xml:"version,attr,omitempty"`
			} `xml:"service"`
		} `xml:"port"`
	} `xml:"ports"`
	OS struct {
		OSMatches []struct {
			Name      string `xml:"name,attr"`
			Accuracy  string `xml:"accuracy,attr"`
			OSClasses []struct {
				Type     string `xml:"type,attr"`
				Vendor   string `xml:"vendor,attr"`
				OSFamily string `xml:"osfamily,attr"`
				OSGen    string `xml:"osgen,attr"`
			} `xml:"osclass"`
		} `xml:"osmatch"`
	} `xml:"os"`
}

// Status represents the status of a host
type Status struct {
	State string `xml:"state,attr"`
}

// Address represents an address of a host
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}
