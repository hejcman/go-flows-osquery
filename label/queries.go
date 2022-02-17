package osquery_label

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"strconv"
)

// Used as a single entry point for executing SQL requests on the OSQuery client.
// Parses the response and handles errors.
func (q *osqueryLabels) execQuery(sql string) ([]map[string]string, error) {
	response, err := q.client.Query(sql)
	if err != nil {
		return nil, err
	} else {
		return response.Response, nil
	}
}

// Get the PID of the process which created the packet, or which receives it.
// This is decided based on the source and destination ports and addresses.
func (q *osqueryLabels) getProcessPid(packet gopacket.Packet) (string, error) {
	var srcIp, dstIp, srcPort, dstPort, pid, sql string

	if ipLayer4 := packet.Layer(layers.LayerTypeIPv4); ipLayer4 != nil {
		ip, _ := ipLayer4.(*layers.IPv4)
		srcIp = ip.SrcIP.String()
		dstIp = ip.DstIP.String()
	} else if ipLayer6 := packet.Layer(layers.LayerTypeIPv6); ipLayer6 != nil {
		ip, _ := ipLayer6.(*layers.IPv6)
		srcIp = ip.SrcIP.String()
		dstIp = ip.DstIP.String()
	} else {
		srcIp = ""
		dstIp = ""
	}

	// TODO: Cleanup.
	if layer := packet.Layer(layers.LayerTypeTCP); layer != nil {
		tcp, _ := layer.(*layers.TCP)
		srcPort = strconv.Itoa(int(tcp.SrcPort))
		dstPort = strconv.Itoa(int(tcp.DstPort))
	} else if layer := packet.Layer(layers.LayerTypeUDP); layer != nil {
		udp, _ := layer.(*layers.UDP)
		srcPort = strconv.Itoa(int(udp.SrcPort))
		dstPort = strconv.Itoa(int(udp.DstPort))
	} else if layer := packet.Layer(layers.LayerTypeRUDP); layer != nil {
		rudp, _ := layer.(*layers.RUDP)
		srcPort = strconv.Itoa(int(rudp.SrcPort))
		dstPort = strconv.Itoa(int(rudp.DstPort))
	} else if layer := packet.Layer(layers.LayerTypeSCTP); layer != nil {
		sctp, _ := layer.(*layers.SCTP)
		srcPort = strconv.Itoa(int(sctp.SrcPort))
		dstPort = strconv.Itoa(int(sctp.DstPort))
	} else if layer := packet.Layer(layers.LayerTypeUDPLite); layer != nil {
		udplite, _ := layer.(*layers.UDPLite)
		srcPort = strconv.Itoa(int(udplite.SrcPort))
		dstPort = strconv.Itoa(int(udplite.DstPort))
	} else {
		srcPort = ""
		dstPort = ""
	}

	if srcPort == "" && dstPort == "" {
		sql = "SELECT pid FROM process_open_sockets WHERE " +
			"(local_address='" + srcIp + "' AND " +
			"remote_address='" + dstIp + "') OR " +
			"(local_address='" + dstIp + "' AND " +
			"remote_address='" + srcIp + "') LIMIT 1;\r\n"
	} else {
		sql = "SELECT pid FROM process_open_sockets WHERE (" +
			"local_address='" + srcIp + "' AND " +
			"remote_address='" + dstIp + "' AND " +
			"local_port='" + srcPort + "' AND " +
			"remote_port='" + dstPort + "') OR (" +
			"local_address='" + dstIp + "' AND " +
			"remote_address='" + srcIp + "' AND " +
			"local_port='" + dstPort + "' AND " +
			"remote_port='" + srcPort + "') LIMIT 1;\r\n"
	}

	tmp, _ := q.execQuery(sql)
	if len(tmp) == 0 {
		pid = ""
	} else {
		pid = tmp[0]["pid"]
	}

	return pid, nil
}

// Get the name of the process based on the PID.
func (q *osqueryLabels) getProcessName(pid string) (string, error) {
	sql := "SELECT name FROM processes WHERE pid='" + pid + "' LIMIT 1;"
	tmp, err := q.execQuery(sql)
	if err != nil {
		return "", err
	}

	if len(tmp) == 0 {
		return "", nil
	} else {
		return tmp[0]["name"], nil
	}
}
