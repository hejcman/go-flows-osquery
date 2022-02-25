package osquery_feature

import (
	"fmt"
	"strconv"

	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-ipfix"
)

type osFeature struct {
	flows.BaseFeature
	tag interface{}
}

// prepareOsFeature extract the necessary os information
func prepareOsFeature(tag string, t ipfix.Type) *osFeature {
	osf := &osFeature{}
	c := getOsqueryClient()
	info, err := c.getOsInfo(tag)
	if err != nil {
		panic(fmt.Errorf("problem getting os info"))
		return nil
	}
	c.client.Close()

	// Converting string to integer if necessary.
	var val interface{}
	switch t {
	case ipfix.Unsigned8Type:
		val, _ = strconv.ParseUint(info, 10, 8)
	case ipfix.Unsigned16Type:
		val, _ = strconv.ParseUint(info, 10, 16)
	case ipfix.Unsigned32Type:
		val, _ = strconv.ParseUint(info, 10, 32)
	case ipfix.Unsigned64Type:
		val, _ = strconv.ParseUint(info, 10, 64)
	default:
		val = info
	}

	osf.tag = val
	return osf
}

// Stop is called when the flow ends. We override only this function, as all the other Feature
// functions are not used.
func (osf *osFeature) Stop(_ flows.FlowEndReason, context *flows.EventContext) {
	osf.BaseFeature.SetValue(osf.tag, context, osf)
}
