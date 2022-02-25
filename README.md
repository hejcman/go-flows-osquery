# go-flows-osquery

Modules for the flow exporter [go-flows](https://github.com/CN-TU/go-flows) which add support
for annotating packets and flows with information from [OSQuery](https://www.osquery.io).

Specifically, this repository implements two modules, the [label](/label) for labeling individual
packets with process information, and the [features](/features) which are used to annotate the final flows
with system information.

Note: using the labels plugin is not tested yet.

## Supported features

| CESNET feature name     | Temporary feature name      | Description                                     |
|-------------------------|-----------------------------|-------------------------------------------------|
| `OSQueryProgramName`    | ``__osqueryProcess``        | the process which created the flow              |
| `OSQueryKernelVersion`  | ``__osqueryKernelVersion``  | kernel version                                  |
| `OSQueryOSName`         | ``__osqueryOsName``         | distribution or product name                    |
| ---                     | ``__osqueryOsVersion``      | pretty, suitable for representation, os version |
| `OSQueryOSMajor`        | ``__osqueryOsMajor``        | major release version                           |
| `OSQueryOSMinor`        | ``__osqueryOsMinor``        | minor release version                           |
| ---                     | ``__osqueryOsPatch``        | optional patch release                          |
| `OSQueryOSBuild`        | ``__osqueryOsBuild``        | optional build-specific or variant string       |
| `OSQueryOSPlatform`     | ``__osqueryOsPlatform``     | os platform or id                               |
| `OSQueryOSPlatformLike` | ``__osqueryOsPlatformLike`` | closely related platforms                       |
| ---                     | ``__osqueryOsCodename``     | os version codename                             |
| `OSQueryOSArch`         | ``__osqueryOsArch``         | os architecture                                 |

## Running

Either compile go-flows yourself based on the instructions in the [Compile section](#compiling) or download a ready-made
binary from the [releases](https://github.com/hejcman/go-flows-osquery/releases) page.

The files `features.json` and `osquery.yaml` must be in the same directory as `go-flows`, and they can be found in the
[docs](/docs) folder. To use osquery features, you need to set the osquery socket correctly in the `osquery.yaml` file.
Ofcourse, you need to have osquery installed and running (instructions [here](https://osquery.readthedocs.io/en/stable/)).

```shell
sudo ./go-flows run features features.json export csv test.csv source libpcap -live <ifc>
```

## Compiling

By default, the compiled version is using the CESNET fields. However, if you want to use the temporary fields, pass the
following flag to `go build`: `-ldflag="-X 'github.com/hejcman/go-flows-osquery/features.BuildType=TEMPORARY'"`

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
