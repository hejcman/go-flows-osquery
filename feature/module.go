package osquery_feature

import (
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-flows/packet"
	"github.com/osquery/osquery-go"
)

type osqueryFeature struct {
	flows.BaseFeature

	// The client used to communicate with osquery.
	client    *osquery.ExtensionManagerClient

	// A cache of all the received process identifications. The flow is annotated with the most frequently
	// encountered process name.
	processes map[string]uint32

	// A cache of information about the operating system, so that osquery will be asked only once.
	osInfo    map[string]string
}

// Start is called when a new flow is created and not initialized.
func (q *osqueryFeature) Start(context *flows.EventContext) {
	q.BaseFeature.Start(context)
}

// Event is called everytime an event occurs on the flows, for example when a packet is added.
func (q *osqueryFeature) Event(new interface{}, context *flows.EventContext, src interface{}) {
	buf := new.(packet.Buffer)
	println(buf.Metadata())
	println(buf.Key())
}

// Stop is called when the flow ends.
func (q *osqueryFeature) Stop(reason flows.FlowEndReason, context *flows.EventContext) {

}

