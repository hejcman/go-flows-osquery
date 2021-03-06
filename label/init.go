package osquery_label

import (
	"fmt"
	"os"
	"time"

	"github.com/CN-TU/go-flows/packet"
	"github.com/CN-TU/go-flows/util"
	"github.com/osquery/osquery-go"
	"github.com/spf13/viper"
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

	// Parsing the config file
	viper.SetConfigName("osquery.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %w \n", err))
	}

	// Preparing the module
	module := &osqueryLabels{}
	// FIXME: Use osquery_timeout
	err = module.openClient(viper.GetString("osquery_socket"))
	if err != nil {
		return nil, nil, err
	}
	module.id = fmt.Sprint("osqueryLabel|", viper.GetString("osquery_socket"))
	module.cache = map[string]string{}

	return args, module, nil
}

// The help string.
func osqueryLabelsHelp(name string) {
	_, _ = fmt.Fprintf(os.Stderr, "The only argument to %s must be the path to the osquery socket.", name)
}

// Used to register the module as an extension to go-flows.
func init() {
	packet.RegisterLabel(
		"osquery",
		"Label packets with OSQuery information.",
		newOsqueryLabels,
		osqueryLabelsHelp)
}
