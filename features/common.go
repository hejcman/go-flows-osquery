package osquery_feature

import (
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-ipfix"
)

/*
╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
│ Common variables and definitions │
╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯
*/

// CesnetPen is the pen of CESNET, as defined by RFC 7013
// https://datatracker.ietf.org/doc/html/draft-ietf-ipfix-ie-doctors#section-10.1
var CesnetPen uint32 = 8057

/*
╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
│ Init function │
╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯
*/

func init() {

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ Process Name │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryProgramName",
			CesnetPen,
			852,
			ipfix.StringType,
			ipfix.VariableLength),
		"the process which created the flow",
		flows.FlowFeature,
		func() flows.Feature { return &processFeature{} },
		flows.RawPacket,
	)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ Kernel version │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryKernelVersion",
			CesnetPen,
			861,
			ipfix.StringType,
			ipfix.VariableLength),
		"kernel version",
		flows.FlowFeature,
		func() flows.Feature { return prepareKernelFeature("version") },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╮
	// │ OS Name │
	// ╰╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSName",
			CesnetPen,
			854,
			ipfix.StringType,
			ipfix.VariableLength),
		"distribution or product name",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("major", ipfix.StringType) },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ OS Major Version │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSMajor",
			CesnetPen,
			855,
			ipfix.Unsigned16Type,
			0),
		"major release version",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("major", ipfix.Unsigned16Type) },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ OS Minor Version │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSMinor",
			CesnetPen,
			856,
			ipfix.Unsigned16Type,
			0),
		"minor release version",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("minor", ipfix.Unsigned16Type) },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ OS Patch Version │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSBuild",
			CesnetPen,
			857,
			ipfix.StringType,
			ipfix.VariableLength),
		"optional build-specific or variant string",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("build", ipfix.StringType) },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ OS Platform │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSPlatform",
			CesnetPen,
			858,
			ipfix.StringType,
			ipfix.VariableLength),
		"os platform or id",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("platform", ipfix.StringType) },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ OS Platform like │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSPlatformLike",
			CesnetPen,
			859,
			ipfix.StringType,
			ipfix.VariableLength),
		"closely related platforms",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("platform_like", ipfix.StringType) },
		flows.RawPacket)

	// ╭╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╶╮
	// │ OS Architecture │
	// ╰╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╴╯

	flows.RegisterFeature(
		ipfix.NewInformationElement(
			"OSQueryOSArch",
			CesnetPen,
			860,
			ipfix.StringType,
			ipfix.VariableLength),
		"os architecture",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("arch", ipfix.StringType) },
		flows.RawPacket)

}
