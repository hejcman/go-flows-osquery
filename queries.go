package go_flows_osquery

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Used as a single entry point for executing SQL requests on the OSQuery client.
// Parses the response and handles errors.
func (q *osqueryLabels) execQuery(sql string) (string, error) {
	response, err := q.client.Query(sql)
	if err != nil {
		return "", err
	} else {
		return response.String(), nil
	}
}

// Get the PID of the process which created the packet, or which receives it.
// This is decided based on the source and destination ports and addresses.
func (q *osqueryLabels) getProcessPid(packet gopacket.Packet) (string, error) {
	var srcIp, dstIp, srcPort, dstPort string

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIp = ip.SrcIP.String()
		dstIp = ip.DstIP.String()
	}

	// TODO: Add parsing for other protocols
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp, _ := layer.(*layers.TCP)
		srcPort = tcp.SrcPort.String()
		dstPort = tcp.DstPort.String()
	}

	sql := "SELECT pid FROM process_open_sockets WHERE (" +
		"local_address='" + srcIp + "' AND " +
		"remote_address='" + dstIp + "' AND " +
		"local_port='" + srcPort + "' AND " +
		"remote_port='" + dstPort + "') OR (" +
		"local_address='" + dstIp + "' AND " +
		"remote_address='" + srcIp + "' AND " +
		"local_port='" + dstPort + "' AND " +
		"remote_port='" + srcPort + "') LIMIT 1;"

	return q.execQuery(sql)
}

// Get the name of the process based on the PID.
func (q *osqueryLabels) getProcessName(pid string) (string, error) {
	sql := "SELECT name FROM processes WHERE pid='" + pid + "' LIMIT 1;"

	return q.execQuery(sql)
}
