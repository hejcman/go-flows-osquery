# go-flows-osquery

Modules for the flow exporter [go-flows](https://github.com/CN-TU/go-flows) which add support
for annotating packets and flows with information from [OSQuery](https://www.osquery.io).

Specifically, this repository implements two modules, the [label](/label) for labeling individual
packets with process information, and the [feature](/feature) which is used to annotate the final flows
with system information.

## Supported features

| Feature name                | Description                                     |
|-----------------------------|-------------------------------------------------|
| ``__osqueryProcess``        | the process which created the flow              |
| ``__osqueryKernelVersion``  | kernel version                                  |
| ``__osqueryOsName``         | distribution or product name                    |
| ``__osqueryOsVersion``      | pretty, suitable for representation, os version |
| ``__osqueryOsMajor``        | major release version                           |
| ``__osqueryOsMinor``        | minor release version                           |
| ``__osqueryOsPatch``        | optional patch release                          |
| ``__osqueryOsBuild``        | optional build-specific or variant string       |
| ``__osqueryOsPlatform``     | os platform or id                               |
| ``__osqueryOsPlatformLike`` | closely related platforms                       |
| ``__osqueryOsCodename``     | os version codename                             |
| ``__osqueryOsArch``         | os architecture                                 |

## Compiling

```shell
git clone https://github.com/CN-TU/go-flows.git
cd go-flows/modules
git clone https://github.com/hejcman/go-flows-osquery.git
cd ../go-flows-build
go build
go get github.com/osquery/osquery-go
./go-flows-build +go-flows-osquery.label +go-flows-osquery.features -features.staging build
```

## Running

```shell
sudo ./go-flows run features label.json label osquery <osquery socket path> export csv csv test.csv source libptrap -live <ifc>
```
