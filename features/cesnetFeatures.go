package osquery_feature

import (
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-ipfix"
)

func registerCesnetFeatures() {
	registerCesnetProcessFeatures()
	registerCesnetKernelFeatures()
	registerCesnetOsFeatures()
}

// registerCesnetProcessFeatures registers CESNET features
// regarding the process annotated to the flow.
func registerCesnetProcessFeatures() {
	// PROCESS NAME
	flows.RegisterFeature(
		ipfix.InformationElement{
			Name:   "OSQueryProgramName",
			Pen:    CesnetPen,
			ID:     852,
			Type:   ipfix.StringType,
			Length: ipfix.VariableLength,
		},
		"the process which created the flow",
		flows.FlowFeature,
		func() flows.Feature { return &processFeature{} },
		flows.RawPacket,
	)
}

// registerCesnetKernelFeatures registers CESNET features regarding the OS kernel
func registerCesnetKernelFeatures() {
	// KERNEL VERSION
	flows.RegisterFeature(
		ipfix.InformationElement{
			Name:   "OSQueryKernelVersion",
			Pen:    CesnetPen,
			ID:     861,
			Type:   ipfix.StringType,
			Length: ipfix.VariableLength,
		},
		"kernel version",
		flows.FlowFeature,
		func() flows.Feature { return prepareKernelFeature("version") },
		flows.RawPacket)
}

// registerCesnetOsFeatures registers CESNET features regarding the OS information
func registerCesnetOsFeatures() {
	// OS NAME
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
	// OS MAJOR VERSION
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
	// OS MINOR VERSION
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
	// OS PATCH VERSION
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
	// OS PLATFORM
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
	// OS PLATFORM-LIKE
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
	//// OS ARCH
	flows.RegisterFeature(
		ipfix.InformationElement{
			Name:   "OSQueryOSArch",
			Pen:    CesnetPen,
			ID:     860,
			Type:   ipfix.StringType,
			Length: ipfix.VariableLength,
		},
		"os architecture",
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("arch", ipfix.StringType) },
		flows.RawPacket)
}
