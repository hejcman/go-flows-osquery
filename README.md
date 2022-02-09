# go-flows-osquery

Modules for the flow exporter [go-flows](https://github.com/CN-TU/go-flows) which add support
for annotating packets and flows with information from [OSQuery](https://www.osquery.io).

Specifically, this repository implements two modules, the [label]("/label") for labeling individual
packets with process information, and the [export]("/export") which is used to annotate the final flows
with system information.
