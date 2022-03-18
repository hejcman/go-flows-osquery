package osquery_feature

import (
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-flows/packet"
	"github.com/google/gopacket/layers"
	"strconv"
)

type processFeature struct {
	flows.BaseFeature
	client *osqueryClient
}

func (procf *processFeature) Start(context *flows.EventContext) {
	procf.BaseFeature.Start(context)
	// FIXME: Opening a new osquery client with each flow might not be very fast.
	procf.client = getOsqueryClient()
}

func (procf *processFeature) Event(new interface{}, context *flows.EventContext, _ interface{}) {

	// If we already have the process name, we can quit.
	if procf.Value() != nil {
		return
	}

	var srcIp, dstIp, srcPort, dstPort, process string

	buf := new.(packet.Buffer)

	// First, we filter common protocols that make no sense associating with a process to speed up execution.
	if layer := buf.Layer(layers.LayerTypeDNS); layer != nil {
		process = "DNS"
	} else if layer := buf.Layer(layers.LayerTypeDHCPv4); layer != nil {
		process = "DHCPv4"
	} else if layer := buf.Layer(layers.LayerTypeDHCPv6); layer != nil {
		process = "DHCPv6"
	}

	if process != "" {
		procf.SetValue(process, context, procf)
		// TODO: Fix this, this is ugly.
		procf.client.client.Close()
		return
	}

	// Deciding what IP version is used
	if ipLayer4 := buf.Layer(layers.LayerTypeIPv4); ipLayer4 != nil {
		ip, _ := ipLayer4.(*layers.IPv4)
		srcIp = ip.SrcIP.String()
		dstIp = ip.DstIP.String()
	} else if ipLayer6 := buf.Layer(layers.LayerTypeIPv6); ipLayer6 != nil {
		ip, _ := ipLayer6.(*layers.IPv6)
		srcIp = ip.SrcIP.String()
		dstIp = ip.DstIP.String()
	} else {
		return
	}

	// Parsing the layers to find the source and destination IP
	if layer := buf.Layer(layers.LayerTypeTCP); layer != nil {
		tcp, _ := layer.(*layers.TCP)
		srcPort = strconv.Itoa(int(tcp.SrcPort))
		dstPort = strconv.Itoa(int(tcp.DstPort))
	} else if layer := buf.Layer(layers.LayerTypeUDP); layer != nil {
		udp, _ := layer.(*layers.UDP)
		srcPort = strconv.Itoa(int(udp.SrcPort))
		dstPort = strconv.Itoa(int(udp.DstPort))
	} else if layer := buf.Layer(layers.LayerTypeRUDP); layer != nil {
		rudp, _ := layer.(*layers.RUDP)
		srcPort = strconv.Itoa(int(rudp.SrcPort))
		dstPort = strconv.Itoa(int(rudp.DstPort))
	} else if layer := buf.Layer(layers.LayerTypeSCTP); layer != nil {
		sctp, _ := layer.(*layers.SCTP)
		srcPort = strconv.Itoa(int(sctp.SrcPort))
		dstPort = strconv.Itoa(int(sctp.DstPort))
	} else if layer := buf.Layer(layers.LayerTypeUDPLite); layer != nil {
		udplite, _ := layer.(*layers.UDPLite)
		srcPort = strconv.Itoa(int(udplite.SrcPort))
		dstPort = strconv.Itoa(int(udplite.DstPort))
	} else {
		srcPort = ""
		dstPort = ""
	}

	// Getting the name of the process and closing the connection to OSQuery
	pid, err := procf.client.getProcessID(srcIp, dstIp, srcPort, dstPort)
	if err != nil {
		procf.SetValue("unknown", context, procf)
		procf.client.client.Close()
		return
	}
	process, err = procf.client.getProcessName(pid)
	if err != nil {
		procf.SetValue("unknown", context, procf)
		procf.client.client.Close()
		return
	}

	procf.SetValue(process, context, procf)
	// TODO: Fix this, this is ugly.
	procf.client.client.Close()
}
