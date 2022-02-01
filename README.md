Sozune
====

Sozune (pronounce Sozuné) is a modern HTTP reverse proxy and load balancer.

It supports several backends (Docker, Ring (https://github.com/kemeter/ring), firecraker(soon)) to manage its configuration automatically and dynamically (hot-reload).

## Quick start

use the official tiny Docker image and run

    $ docker run -d -p 80:80 kemeter/sozune

Or get the sources:

    $ cargo build
    $ cargo run


### Test it
```bash 
sozune:
  image: kemeter/sozune
  ports:
    - "80:80"
  volumes:
    - /var/run/docker.sock:/var/run/docker.sock

whoami1:
  image: traefik/whoami
  labels:
    - "sozune.host=whoami.docker.localhost"

whoami2:
  image: traefik/whoami
  labels:
    - "sozune.host=whoami.docker.localhost"

```
