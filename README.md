# vunnel

A vulnerability data funnel... a `vunnel`! (someone should really find a better name)

Run locally:
```
# prepare environment
poetry shell
poetry install

# run...
vunnel list
vunnel run -p centos

# output in the ./data directory
```

...or run in a containerized environment:
```
docker-compose run vunnel run -p centos

# output in the ./data directory
```
