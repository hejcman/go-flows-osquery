package osquery_feature

import (
	"fmt"
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-flows/packet"
	"github.com/CN-TU/go-ipfix"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
	"strconv"
)

// Start is called when a new flow is created and not initialized.
func (c *osqueryFeature) Start(context *flows.EventContext) {
	c.BaseFeature.Start(context)
}

// Event is called everytime an event occurs on the flows, for example when a packet is added.
func (c *osqueryFeature) Event(new interface{}, context *flows.EventContext, src interface{}) {
	if !c.process || c.queried {
		return
	}

	var srcIp, dstIp, srcPort, dstPort string

	c.tag = "unknown"
	buf := new.(packet.Buffer)

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
	pid, err := c.getProcessID(srcIp, dstIp, srcPort, dstPort)
	if err != nil {
		return
	}
	name, err := c.getProcessName(pid)
	if err != nil {
		return
	}
	c.tag = name
	c.queried = true
	c.client.Close()
}

// Stop is called when the flow ends.
func (c *osqueryFeature) Stop(reason flows.FlowEndReason, context *flows.EventContext) {
	c.BaseFeature.SetValue(c.tag, context, c)
}

func prepareFeature() *osqueryFeature {
	// Parsing the config file
	viper.SetConfigName("osquery.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error when reading config file: %w \n", err))
	}

	c := &osqueryFeature{}
	// Preparing the client
	err = c.openClient(viper.GetString("osquery_socket"))
	if err != nil {
		panic(fmt.Errorf("Fatal error getting osquery socket: %w \n", err))
		return nil
	}
	c.process = true
	c.queried = false
	return c
}

// Used for specifically preparing OS features, which make a request to the
// osquery client, cache the results, and then close the connection.
func prepareOsFeature(param string) *osqueryFeature {

	c := prepareFeature()
	c.process = false
	defer c.client.Close()

	// Caching the specific OS info
	tmp, err := c.getOsInfo(param)
	if err != nil {
		panic(fmt.Errorf("Fatal problem getting OS info: %w \n", err))
	}
	c.tag = tmp
	return c
}

func init() {
	/////////////////////
	// PROCESS FEATURE //
	/////////////////////

	flows.RegisterTemporaryFeature(
		"__osqueryProcess",
		"the process which created the flow",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareFeature() },
		flows.RawPacket)

	/////////////////
	// OS FEATURES //
	/////////////////

	// OS NAME
	flows.RegisterTemporaryFeature(
		"__osqueryOsName",
		"distribution or product name",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("name") },
		flows.RawPacket)
	// OS VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsVersion",
		"pretty, suitable for representation, os version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("version") },
		flows.RawPacket)
	// OS MAJOR VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsMajor",
		"major release version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("major") },
		flows.RawPacket)
	// OS MINOR VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsMinor",
		"minor release version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("minor") },
		flows.RawPacket)
	// OS PATCH VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsPatch",
		"optional patch release",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("patch") },
		flows.RawPacket)
	// OS BUILD
	flows.RegisterTemporaryFeature(
		"__osqueryOsBuild",
		"optional build-specific or variant string",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("build") },
		flows.RawPacket)
	// OS PLATFORM
	flows.RegisterTemporaryFeature(
		"__osqueryOsPlatform",
		"os platform or id",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("platform") },
		flows.RawPacket)
	// OS PLATFORM-LIKE
	flows.RegisterTemporaryFeature(
		"__osqueryOsPlatformLike",
		"closely related platforms",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("platform_like") },
		flows.RawPacket)
	// OS CODENAME
	flows.RegisterTemporaryFeature(
		"__osqueryOsCodename",
		"os version codename",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("codename") },
		flows.RawPacket)
	// OS ARCH
	flows.RegisterTemporaryFeature(
		"__osqueryOsArch",
		"os architecture",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("arch") },
		flows.RawPacket)
}
