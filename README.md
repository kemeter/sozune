# Sōzune

Sōzune (pronounce Sozuné) is a modern reverse proxy and load balancer that simplifies microservices deployment. Sōzune integrates with your existing infrastructure components (Docker, Swarm, Kubernetes, etc.) and configures itself automatically and dynamically.

## 🚀 Features

- **Automatic discovery** of Docker containers via labels
- **Hot reload** - real-time change detection
- **Wildcard support** - hostnames like `*.example.com`
- **Multi-protocol** - HTTP, HTTPS, TCP, UDP
- **Automatic load balancing** between multiple instances
- **Flexible configuration** via Docker labels or YAML files
- **REST API** for monitoring and debugging

## 📦 Installation

```bash
# Clone the repo
git clone <repo-url>
cd sozune

# Build
cargo build --release

# Run
./target/release/sozune
```

## ⚙️ Configuration

### Via Docker Labels

Add labels to your Docker containers:

```bash
docker run -d \
  -l sozune.enable=true \
  -l sozune.http.web.host=example.com,www.example.com \
  -l sozune.http.web.port=8080 \
  -l sozune.http.web.tls=true \
  nginx
```

#### Supported Labels

**Activation**:
- `sozune.enable=true` - Enables Sōzune for this container

**HTTP/HTTPS**:
- `sozune.http.<service>.host` - Hostnames (required), comma-separated
- `sozune.http.<service>.port` - Service port (default: 80)
- `sozune.http.<service>.path` - Exact path to match
- `sozune.http.<service>.prefix` - Path prefix (default: `/`)
- `sozune.http.<service>.tls` - Enable HTTPS (default: false)
- `sozune.http.<service>.stripPrefix` - Strip prefix before proxying
- `sozune.http.<service>.priority` - Routing priority (default: 0)

**Authentication**:
- `sozune.http.<service>.auth.basic` - Basic auth: `user1:hash1,user2:hash2`

**Headers**:
- `sozune.http.<service>.headers.<name>` - Custom headers

**TCP/UDP**:
- `sozune.tcp.<service>.host` - Hostname
- `sozune.tcp.<service>.port` - Port
- `sozune.udp.<service>.host` - Hostname
- `sozune.udp.<service>.port` - Port

### Examples

**Simple web service**:
```bash
docker run -d \
  -l sozune.enable=true \
  -l sozune.http.app.host=myapp.local \
  -l sozune.http.app.port=3000 \
  my-webapp
```

**With HTTPS and authentication**:
```bash
docker run -d \
  -l sozune.enable=true \
  -l sozune.http.admin.host=admin.myapp.local \
  -l sozune.http.admin.port=8080 \
  -l sozune.http.admin.tls=true \
  -l sozune.http.admin.auth.basic=admin:$2b$10$hash \
  admin-panel
```

**Wildcards and multiple services**:
```bash
docker run -d \
  -l sozune.enable=true \
  -l sozune.http.api.host=*.api.myapp.local \
  -l sozune.http.api.port=8000 \
  -l sozune.http.api.prefix=/v1 \
  -l sozune.http.web.host=myapp.local \
  -l sozune.http.web.port=80 \
  full-stack-app
```

**TCP service**:
```bash
docker run -d \
  -l sozune.enable=true \
  -l sozune.tcp.database.host=db.myapp.local \
  -l sozune.tcp.database.port=5432 \
  postgres
```

### Automatic Reload

Sōzune automatically detects Docker changes:

- **Container started** → Adds entrypoints to proxy
- **Container stopped** → Removes backends, deletes if no more backends
- **Container updated** → Removes old + adds new
- **Labels modified** → Automatic reconfiguration

No need to restart Sōzune!

### Via configuration file

Create `config.yaml`:

```yaml
providers:
  docker:
    enabled: true
    expose_by_default: false
  config_file:
    enabled: false
    path: "entrypoints.yaml"

proxy:
  http:
    listen_address: 8080
    #listen_address: 127.0.0.1:8080
  https:
    listen_address: 8443
  max_buffers: 500
  buffer_size: 16384
  startup_delay_ms: 1000
  cluster_setup_delay_ms: 500
```

Environment variables:
- `SOZUNE_CONFIG_PATH` - Config file path (default: `config.yaml`)
- `SOZUNE_HTTP_PORT` - HTTP port (default: 8080)
- `SOZUNE_HTTPS_PORT` - HTTPS port (default: 8443)





## 🌐 REST API

The API runs on `http://localhost:3035`:

- `GET /entrypoints` - Lists all configured entrypoints

## 🔧 Load Balancing

Multiple containers with the same labels are automatically load-balanced:

```bash
# Instance 1
docker run -d -l sozune.enable=true -l sozune.http.app.host=myapp.local app:v1

# Instance 2  
docker run -d -l sozune.enable=true -l sozune.http.app.host=myapp.local app:v1

# Instance 3
docker run -d -l sozune.enable=true -l sozune.http.app.host=myapp.local app:v1
```

Sōzu automatically performs round-robin between the 3 instances.

## 🛠️ Architecture

```
┌─────────────────┐       ┌─────────────────┐       
│   Docker API    │ ─────▶│     Sōzune      │       
│   (Events)      │       │  (Discovery)    │       
└─────────────────┘       └─────────────────┘       
                           ▲       │
                           │       │
┌─────────────────┐        │       │
│   Config File   │────────┘       │
│  (Entrypoints)  │                │    
└─────────────────┘                │  
                                   │
                                   ▼
                           ┌─────────────────┐       ┌─────────────────┐
                           │     Storage     │──────▶│      Proxy      │
                           │  (Entrypoints)  │       │     (Sōzu)      │
                           └─────────────────┘       └─────────────────┘
                                    │
                                    ▼
                           ┌─────────────────┐
                           │    API REST     │
                           │  (Monitoring)   │
                           └─────────────────┘ 
```

1. **Docker Provider** - Listens to Docker events in real-time
2. **Config File Provider** - Reads YAML configuration files
3. **Storage** - Centralized entrypoints state (thread-safe)
4. **Proxy** - HTTP/HTTPS workers configured dynamically
5. **REST API** - Monitoring and debugging interface

## 📋 Logs

```bash
# Logs with debug level
RUST_LOG=debug ./target/release/sozune

# Sōzune logs only
RUST_LOG=sozune=info ./target/release/sozune
```



## 🚦 Default ports

- **8080** - HTTP Proxy
- **8443** - HTTPS Proxy
- **3035** - REST API

## 🤝 Contributors

Pull requests welcome!

## 📄 License

MIT License
