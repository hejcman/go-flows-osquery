package label

import (
	"errors"
	"flag"
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
func newOsqueryLabels(args []string) ([]string, util.Module, error) {

	var socket string

	// Parsing the arguments
	flagSet := flag.NewFlagSet("socket", flag.ExitOnError)
	flagSet.Usage = func() { osqueryLabelsHelp("OsqueryLabels") }
	flagSet.StringVar(&socket, "socket", "", "The path to the OSQuery socket.")

	err := flagSet.Parse(args)
	if err != nil {
		return nil, nil, err
	}

	if flagSet.NArg() < 1 {
		return nil, nil, errors.New("no OSQuery socket specified")
	}

	// Preparing the module
	module := &osqueryLabels{}
	err = module.openClient(socket)
	if err != nil {
		return nil, nil, err
	}
	module.id = fmt.Sprint("osqueryLabels|", args[0])
	module.cache = map[string]string{}

	return flagSet.Args()[1:], module, nil
}

// The help string.
func osqueryLabelsHelp(name string) {
	_, _ = fmt.Fprintf(os.Stderr, "Help string.")
}

// Used to register the module as an extension to go-flows.
func init() {
	packet.RegisterLabel(
		"osqueryLabels",
		"Label packets with OSQuery information.",
		newOsqueryLabels,
		osqueryLabelsHelp)
}
