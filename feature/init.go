package osquery_feature

import (
	"fmt"
	"time"

	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-ipfix"
	"github.com/osquery/osquery-go"
	"github.com/spf13/viper"
)

func (q *osqueryFeature) openClient(socket string) (err error) {
	client, err := osquery.NewClient(socket, 10*time.Second)
	if err != nil {
		return
	}
	q.client = client
	return nil
}

func prepareFeature() flows.Feature {

	// Parsing the config file
	viper.SetConfigName("osquery.yaml")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	err := viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("Fatal error config file: %w \n", err))
	}

	q := &osqueryFeature{}
	// Preparing the client
	// FIXME: Add support for osquery_timeout.
	err = q.openClient(viper.GetString("osquery_socket"))
	if err != nil {
		panic(fmt.Errorf("Fatal error getting osquery socket: %w \n", err))
		return nil
	}
	// Caching OS info
	err = q.getOsInfo()
	if err != nil {
		panic(fmt.Errorf("Fatal error getting OS info: %w \n", err))
		return nil
	}
	// Cleaning up
	q.client.Close()
	return q
}

func init() {
	// TODO: Include OS info
	flows.RegisterTemporaryFeature(
		"__osName",
		"the name of the operating system",
		ipfix.StringType,
		0,
		flows.FlowFeature,
		prepareFeature,
		flows.RawPacket,
	)
}
