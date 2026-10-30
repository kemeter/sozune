const PROVIDERS = ['Docker', 'Podman', 'Swarm', 'Kubernetes', 'Nomad', 'Consul', 'Ring', 'HTTP', 'File'];

export default function ProxyDiagram() {
  return (
    <section className="flow" aria-label="How Sōzune works">
      <div className="container">
        <div className="flow-diagram">
          <ul className="flow-providers">
            {PROVIDERS.map((p) => (
              <li key={p}>{p}</li>
            ))}
          </ul>

          <div className="flow-updates">
            <span>Configuration &amp; discovery</span>
          </div>

          <div className="flow-node flow-clients">
            <strong>Clients</strong>
          </div>

          <div className="flow-link flow-link-in" aria-hidden="true" />

          <div className="flow-node flow-sozune">
            <strong>Sōzune</strong>
            <ul className="flow-stages">
              <li>HTTP(S), TCP &amp; UDP routing</li>
              <li>Middlewares</li>
            </ul>
          </div>

          <div className="flow-link flow-link-out" aria-hidden="true" />

          <div className="flow-node flow-backends">
            <strong>Backends</strong>
          </div>

          <p className="flow-note">Routing updates without restarts</p>
        </div>

        <ul className="flow-legend">
          <li className="flow-legend-traffic">traffic</li>
          <li className="flow-legend-updates">configuration &amp; discovery</li>
        </ul>
      </div>
    </section>
  );
}
