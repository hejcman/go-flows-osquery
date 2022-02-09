package go_flows_osquery

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/CN-TU/go-flows/packet"
	"github.com/CN-TU/go-flows/util"
	"github.com/osquery/osquery-go"
)

// Used to prepare the client of the module.
// Tries to connect to an open OSQuery socket.
func (q *osqueryLabels) openClient(socket string) (err error) {
	client, err := osquery.NewClient(socket, 10*time.Second)
	if err != nil {
		return
	}
	q.client = client
	return nil
}

// The constructor for the module.
func newGoFlowsOsqueryLabels(args []string) ([]string, util.Module, error) {
	// Parsing the arguments
	if len(args) < 1 {
		return nil, nil, errors.New("no OSQuery socket specified")
	}

	// Preparing the module
	ret := &osqueryLabels{}
	err := ret.openClient(args[0])
	if err != nil {
		return nil, nil, err
	}
	ret.id = fmt.Sprint("osqueryLabels|", args[0])
	ret.cache = map[string]string{}

	return args, ret, nil
}

// The help string.
func goFlowsOsqueryHelp(name string) {
	_, _ = fmt.Fprintf(os.Stderr, "Help string.")
}

// Used to register the module as an extension to go-flows.
func init() {
	packet.RegisterLabel(
		"osquery",
		"Label packets with OSQuery information.",
		newGoFlowsOsqueryLabels,
		goFlowsOsqueryHelp)
}
