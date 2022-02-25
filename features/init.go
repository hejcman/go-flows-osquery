package osquery_feature

var (
	// BuildType functions as a build time flag. To change it to the TEMPORARY version, build this module with the
	// following parameters: -ldflag="-X 'github.com/hejcman/go-flows-osquery/features.BuildType=TEMPORARY'"
	BuildType = "CESNET"

	// CesnetPen is the pen of CESNET, as defined by RFC 7013
	// https://datatracker.ietf.org/doc/html/draft-ietf-ipfix-ie-doctors#section-10.1
	CesnetPen uint32 = 8057
)

func init() {
	if BuildType == "CESNET" {
		registerCesnetFeatures()
	} else {
		registerTemporaryFeatures()
	}
}
