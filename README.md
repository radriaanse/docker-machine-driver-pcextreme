# docker-machine-driver-pcextreme

A docker-machine driver for the PCextreme Aurora cloud
The driver is based on several generic Cloudstack modules as this is what the public API is using.

## Installation

Either compile from source:
```
go get github.com/radriaanse/docker-machine-driver-pcextreme
go install github.com/radriaanse/docker-machine-driver-pcextreme
```

Or grab the binary release and make sure to place it in your `$PATH`.

Run the following to make sure everything is installed correctly:
```
docker-machine create --driver pcextreme
```

## Usage

API credentials can be found in the control panel under 'Aurora Compute' -> 'Users'.

Create a basic machine using defaults:
```
docker-machine create \
  --driver pcextreme \
  --pcextreme-api-key "<key>"
  --pcextreme-api-secret "<secret>"
```

With some cloud-init userdata:
```
docker-machine create \
  --driver pcextreme \
  --pcextreme-api-key "<key>"
  --pcextreme-api-secret "<secret>"
  --pcextreme-service-offering "Stamina 4G"
  --pcextreme-template "Ubuntu 18.04"
  --pcextreme-userdata "./cloud-config"
```

Use a custom template:
```
docker-machine create \
  --driver pcextreme \
  --pcextreme-api-key "<key>"
  --pcextreme-api-secret "<secret>"
  --pcextreme-service-offering "Stamina 4G"
  --pcextreme-template "Archlinux 2018.10"
```

## Options

TODO

## Acknowledgement

The driver is originally written by [@svanharmelen](https://github.com/svanharmelen), [@atsaki](https://github.com/atsaki), [@andrestc](https://github.com/andrestc) & [@dahendel](https://github.com/dahendel).
