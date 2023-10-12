# v2dat

A cli tool that can unpack v2ray data packages (also known as `geoip.dat` and `geosite.dat`) to text files.

## Usage

```shell
v2dat unpack geoip [-d output_dir] [-f tag]... geoip_file
v2dat unpack geosite [-d output_dir] [-f tag[@attr]...]... geosite_file
```

- If `-d` was omitted, the current working dir `.` will be used.
- If no filter `-f` was given. All tags will be unpacked.
- If multiple `@attr` were given. Entries that don't contain any of given attrs will be ignored.
- Unpacked text files will be named as `<geo_filename>_<filter>.txt`.

## Unpacked IP Data

Unpacked IP text files contain a list of CIDRs.

```text
2.16.33.76/32
2.19.128.0/20
2.20.32.0/22
```

## Unpacked Domain Data

`geosite` contains four types of domain rule expression: `domain`, `keyword`, `regexp`, `full`. Each expression can have several attributes `@attr`. More info about `geosite` can be found in [here](https://github.com/v2fly/domain-list-community).

`v2dat` will split type and expression with a `:`. But omits the `domain` prefix and attributes.

```text
google.com
keyword:google
regexp:www\.google\.com$
full:www.google.com
```