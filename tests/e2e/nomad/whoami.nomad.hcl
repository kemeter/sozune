job "sozune-e2e-whoami" {
  type = "service"

  group "web" {
    count = 3

    network {
      port "http" {
        to = 80
      }
    }

    service {
      name     = "whoami"
      provider = "nomad"
      port     = "http"

      tags = [
        "sozune.enable=true",
        "sozune.http.web.host=whoami.nomad-test.localhost",
      ]
    }

    task "server" {
      driver = "docker"

      config {
        image = "traefik/whoami:v1.10"
        ports = ["http"]
      }

      resources {
        cpu    = 50
        memory = 32
      }
    }
  }
}
