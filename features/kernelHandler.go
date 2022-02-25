package osquery_feature

import (
	"fmt"

	"github.com/CN-TU/go-flows/flows"
)

type kernelFeature struct {
	flows.BaseFeature
	tag string
}

// prepareKernelFeature caches the required info about the kernel into the tag.
func prepareKernelFeature(param string) *kernelFeature {
	kernf := &kernelFeature{}
	c := getOsqueryClient()
	info, err := c.getKernelInfo(param)
	if err != nil {
		panic(fmt.Errorf("problem getting kernel info"))
		return nil
	}
	c.client.Close()

	kernf.tag = info
	return kernf
}

// Stop is called when the flow ends. We override only this function,
// as all the other Feature functions are not used.
func (kernf *kernelFeature) Stop(_ flows.FlowEndReason, context *flows.EventContext) {
	kernf.BaseFeature.SetValue(kernf.tag, context, kernf)
}
