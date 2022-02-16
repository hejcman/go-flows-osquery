package label

import (
	"github.com/CN-TU/go-flows/packet"
	"github.com/osquery/osquery-go"
)

type osqueryLabels struct {
	id     string                          // Unique ID of the extension
	client *osquery.ExtensionManagerClient // The client used to communicate with OSQuery.
	cache  map[string]string
}

func (q *osqueryLabels) ID() string {
	return q.id
}

func (q *osqueryLabels) Init() {
}

func (q *osqueryLabels) GetLabel(packet packet.Buffer) (interface{}, error) {
	processPid, err := q.getProcessPid(packet)
	if err != nil {
		return nil, err
	}
	processName, err := q.getProcessName(processPid)
	if err != nil {
		return nil, err
	}
	return processName, nil
}
