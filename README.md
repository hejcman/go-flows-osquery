# go-flows-osquery

Modules for the flow exporter [go-flows](https://github.com/CN-TU/go-flows) which add support
for annotating packets and flows with information from [OSQuery](https://www.osquery.io).

Specifically, this repository implements two modules, the [label](/label) for labeling individual
packets with process information, and the [feature](/feature) which is used to annotate the final flows
with system information.

## Compiling

```shell
git clone https://github.com/CN-TU/go-flows.git
cd go-flows/modules
git clone https://github.com/hejcman/go-flows-osquery.git
cd ../go-flows-build
go build
go get github.com/osquery/osquery-go
./go-flows-build +go-flows-osquery.label build
```

## Running

```shell
sudo ./go-flows run features label.json label osquery <osquery socket path> export csv csv test.csv source libptrap -live <ifc>
```
