package export

import (
	"fmt"
	"github.com/CN-TU/go-flows/flows"
	"github.com/CN-TU/go-flows/util"
	"os"
)

func newOsqueryExport(args []string) ([]string, util.Module, error) {
	return nil, nil, nil
}

func osqueryExportHelp(name string) {
	_, _ = fmt.Fprintf(os.Stderr, "Help string.")
}

func init() {
	flows.RegisterExporter(
		"osqueryExport",
		"Exports flows into IPFIX after annotating them with OSQuery information.",
		newOsqueryExport,
		osqueryExportHelp)
}

