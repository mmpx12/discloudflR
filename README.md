# DiscloudflR

## Discover real ip behind cloudflaire


Its should be only use if other know techniques has failled (dns history, censys, external avatar ...), 
since it can very long and not work every time (filtered port, "Checking your browser before accessing")

This tools whill not work if ports on the target server are filtered (logic) ...


It have some kind of filter:

- `-a|--amazon`        For scan all amazon ip.
- `-s|--service`       For scan specific amazon service (EC2, S3).
- `-c|--country`       For scan all ip from a specific country.
- `-o|--ovh`           For scanning all ovh cluster.
- `-C|--custom-range`  For scan a specific range

without option, it will scan 0.0.0.0/0


### Usage 

```
  -t, --target [URL]              URL with protocol (http://, https://)
  -p, --port   [PORT]             Specify port if not standard
  -a, --amazon                    Check only amazon ips
  -s, --amazon-service [SERVICE]  Specify amazon service (EC2)
  -o, --ovh                       Check only ovh (cluster only)
  -c, --country [COUNTRY CODE]    Check all ip of country 
                                    (don't work with -a, -o, -s, -C)
  -T, --timeout [second]          Timeout in second for curl 
  -C, --custom-range [RANGE]      Custom ip range
```

### Installation

You can compile it with:

```sh
go build discloudflR.go
./discloudflR [OPTIONS]
```

If you are using this way you must be in the directory for usiing it since it use (with -a -c -s) list files.

the other way is docker:

```sh
docker build -t discloudflr:latest .
docker run --rm discloudflr [OPTIONS]
```


exemple:
========

```
  ./discloudflR -t https://xxxxx.ch -T 2.5
      Scan 0.0.0.0 (Very long) with timeout to 2.5 for each requests

  ./discloudflR -t https://xxxxx.ch -c ch
      Scan all ip from switzerland

  ./discloudflR -t https://xxxxx.ch -C X.X.X.X/24
      Scan the custom range X.X.X.X/24

  ./discloudflR -t https://xxxxx.ch -a -s 'EC2'
      Scan only amazon EC2 ips
```
