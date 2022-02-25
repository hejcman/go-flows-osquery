package osquery_feature

import (
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-ipfix"
)

func registerTemporaryFeatures() {
	registerTemporaryProcessFeatures()
	registerTemporaryKernelFeatures()
	registerTemporaryOsFeatures()
}

// Temporary features regarding the process annotated to the flow
func registerTemporaryProcessFeatures() {
	// PROCESS NAME
	flows.RegisterTemporaryFeature(
		"__osqueryProcess",
		"the process which created the flow",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return &processFeature{} },
		flows.RawPacket)
}

// Temporary features regarding the OS kernel
func registerTemporaryKernelFeatures() {
	// KERNEL VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryKernelVersion",
		"kernel version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareKernelFeature("version") },
		flows.RawPacket)
}

// Temporary features regarding the OS information
func registerTemporaryOsFeatures() {
	// OS VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsVersion",
		"pretty, suitable for representation, os version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("version", ipfix.StringType) },
		flows.RawPacket)
	// OS MAJOR VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsMajor",
		"major release version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("major", ipfix.StringType) },
		flows.RawPacket)
	// OS MINOR VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsMinor",
		"minor release version",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("minor", ipfix.StringType) },
		flows.RawPacket)
	// OS PATCH VERSION
	flows.RegisterTemporaryFeature(
		"__osqueryOsPatch",
		"optional patch release",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("patch", ipfix.StringType) },
		flows.RawPacket)
	// OS BUILD
	flows.RegisterTemporaryFeature(
		"__osqueryOsBuild",
		"optional build-specific or variant string",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("build", ipfix.StringType) },
		flows.RawPacket)
	// OS PLATFORM
	flows.RegisterTemporaryFeature(
		"__osqueryOsPlatform",
		"os platform or id",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("platform", ipfix.StringType) },
		flows.RawPacket)
	// OS PLATFORM-LIKE
	flows.RegisterTemporaryFeature(
		"__osqueryOsPlatformLike",
		"closely related platforms",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("platform_like", ipfix.StringType) },
		flows.RawPacket)
	// OS CODENAME
	flows.RegisterTemporaryFeature(
		"__osqueryOsCodename",
		"os version codename",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("codename", ipfix.StringType) },
		flows.RawPacket)
	// OS ARCH
	flows.RegisterTemporaryFeature(
		"__osqueryOsArch",
		"os architecture",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return prepareOsFeature("arch", ipfix.StringType) },
		flows.RawPacket)
}
