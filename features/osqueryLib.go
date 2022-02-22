package osquery_feature

import (
	"errors"
	"github.com/CN-TU/go-flows/flows"
	"github.com/osquery/osquery-go"
	"time"
)

type osqueryFeature struct {
	client *osquery.ExtensionManagerClient
	flows.BaseFeature
	tag string
	queried bool
	process bool
}

// Used to open a connection to the OSQuery client.
func (c *osqueryFeature) openClient(socket string) (err error) {
	client, err := osquery.NewClient(socket, 10*time.Second)
	if err != nil {
		return err
	}
	c.client = client
	return nil
}

// A general function for executing OSQuery queries.
func (c *osqueryFeature) execQuery(sql string) ([]map[string]string, error) {
	response, err := c.client.Query(sql)
	if err != nil {
		return nil, err
	}
	return response.Response, nil
}

// Get OS info based on a parameter. The parameter is one of the rows of the
// os_version table of OSQuery: https://www.osquery.io/schema/5.1.0/#os_version
func (c *osqueryFeature) getOsInfo(param string) (string, error) {
	sql := "SELECT " + param + " FROM os_version LIMIT 1;"
	tmp, err := c.execQuery(sql)
	if err != nil {
		return "", err
	}
	if len(tmp) == 0 {
		return "", errors.New("no results found")
	}
	if val, exists := tmp[0][param]; exists {
		return val, nil
	}
	return "", errors.New("incorrect param specified")
}

// Get the ID of the process which communicates on an open socket, specified by
// the source and destination IP addresses and ports. If no such socket is found,
// returns an empty string and an error.
func (c *osqueryFeature) getProcessID(srcIp, dstIp, srcPort, dstPort string) (string, error) {
	var sql string

	if srcPort == "" || dstPort == "" {
		sql = "SELECT pid FROM process_open_sockets WHERE " +
			"(local_address='" + srcIp + "' AND " +
			"remote_address='" + dstIp + "') OR " +
			"(local_address='" + dstIp + "' AND " +
			"remote_address='" + srcIp + "') LIMIT 1;\r\n"
	} else {
		sql = "SELECT pid FROM process_open_sockets WHERE (" +
			"local_address='" + srcIp + "' AND " +
			"remote_address='" + dstIp + "' AND " +
			"local_port='" + srcPort + "' AND " +
			"remote_port='" + dstPort + "') OR (" +
			"local_address='" + dstIp + "' AND " +
			"remote_address='" + srcIp + "' AND " +
			"local_port='" + dstPort + "' AND " +
			"remote_port='" + srcPort + "') LIMIT 1;\r\n"
	}

	tmp, err := c.execQuery(sql)
	if err != nil {
		return "", err
	}
	if len(tmp) == 0 {
		return "", errors.New("socket not found")
	}
	return tmp[0]["pid"], nil
}

// Gets the name of the process based on the process ID. When no process
// with the specified PID is found, return empty string and error.
func (c *osqueryFeature) getProcessName(pid string) (string, error) {
	sql := "SELECT name FROM processes WHERE pid='" + pid + "' LIMIT 1;"
	tmp, err := c.execQuery(sql)
	if err != nil {
		return "", err
	}
	if len(tmp) == 0 {
		return "", errors.New("process not found")
	}
	return tmp[0]["name"], nil
}
