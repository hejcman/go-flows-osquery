# go-flows-osquery

Modules for the flow exporter [go-flows](https://github.com/CN-TU/go-flows) which add support
for annotating packets and flows with information from [OSQuery](https://www.osquery.io).

Specifically, this repository implements two modules, the [label](/label) for labeling individual
packets with process information, and the [features](/features) which are used to annotate the final flows
with system information.

Note: using the labels plugin is not tested yet.

## Supported features

The CESNET features are designed so that they are compatible with the definitions in [libfds](https://github.com/CESNET/libfds), including the name, PEN, ID, and type.

| CESNET feature name     | Description                                     |
|-------------------------|-------------------------------------------------|
| `OSQueryProgramName`    | the process which created the flow              |
| `OSQueryKernelVersion`  | kernel version                                  |
| `OSQueryOSName`         | distribution or product name                    |
| ---                     | pretty, suitable for representation, os version |
| `OSQueryOSMajor`        | major release version                           |
| `OSQueryOSMinor`        | minor release version                           |
| ---                     | optional patch release                          |
| `OSQueryOSBuild`        | optional build-specific or variant string       |
| `OSQueryOSPlatform`     | os platform or id                               |
| `OSQueryOSPlatformLike` | closely related platforms                       |
| ---                     | os version codename                             |
| `OSQueryOSArch`         | os architecture                                 |

## Running

Compile go-flows based on the instructions in the [Compile section](#compiling).

The files `features.json` and `osquery.yaml` must be in the same directory as `go-flows`, and they can be found in the
[docs](/docs) folder. To use osquery features, you need to set the osquery socket correctly in the `osquery.yaml` file.
Ofcourse, you need to have osquery installed and running (instructions [here](https://osquery.readthedocs.io/en/stable/)).

```shell
sudo ./go-flows run features features.json export csv test.csv source libpcap -live <ifc>
```

## Compiling
### Compiling on Linux or macOS

Compiling on Linux or macOS is quite straightforward:

```shell
git clone https://github.com/CN-TU/go-flows.git
cd go-flows/modules
git clone https://github.com/hejcman/go-flows-osquery.git
cd ../go-flows-build
go build
go get github.com/osquery/osquery-go
./go-flows-build +go-flows-osquery.label +go-flows-osquery.features -features.staging build
```

This will build a binary `go-flows`  in the `go-flows-build` directory.

### Compiling on Windows

For some reason, using `go-flows-build` doesn't work on Windows. To work around this, you need to
modify the `builtin.go` file in the root directory of `go-flows` by appending the following two lines to the imports:

```
_ "github.com/hejcman/go-flows-osquery/features"
_ "github.com/hejcman/go-flows-osquery/label"
```

To download the packages, you need to execute `go get github.com/hejcman/go-flows-osquery`. Finally, building the
exporter can be done by executing `go build .`, which creates a `go-flows.exe` binary file in the root directory.

#### Getting the interface name

Since getting a libpcap compatible interface name is not straightforward on Windows, I prepared a simple program called
`ifcNames`, which outputs all the libpcap usable interface names along with their description. This can be found in the
[ifcNames](/docs/ifcNames) folder. To see the interfaces, execute `go run .` in the ifcNames folder. The interface names
to be used with `go-flows` are in the format `\Device\NPF_{...}`. Whilst this program works on Linux and MacOS as well,
there is no reason to use it as the interfaces names outputed by `ifconfig` work with libpcap.

#### osquery socket name

On Windows, the osquery socket uses backwards slashes for the path. This is not parsable by go-flows, and should be
replaces by forward slashes. For example, `\\.\pipe\shell.em` should be `//./pipe/shell.em`.
