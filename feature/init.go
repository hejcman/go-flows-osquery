package osquery_feature

import (
	"time"

	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-ipfix"
	"github.com/osquery/osquery-go"
)

func (q *osqueryFeature) openClient(socket string) (err error) {
	client, err := osquery.NewClient(socket, 10*time.Second)
	if err != nil {
		return
	}
	q.client = client
	return nil
}

func prepareFeature(socket string) (q *osqueryFeature) {
	q = &osqueryFeature{}
	// Preparing the client
	err := q.openClient(socket)
	if err != nil {
		return nil
	}
	// Caching OS info
	err = q.getOsInfo()
	if err != nil {
		return nil
	}
	// Cleaning up
	q.client.Close()
	return
}

func init() {
	// TODO: Include OS info
	flows.RegisterTemporaryFeature(
		"__processName",
		"The name of the process responsible for this flow.",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		func() flows.Feature { return &osqueryFeature{} },
		flows.PacketFeature,
	)
}
