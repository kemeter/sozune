interface Feature {
  number: string;
  title: string;
  description: string;
}

const FEATURES: Feature[] = [
  {
    number: '01',
    title: 'Multi-platform discovery',
    description:
      'Docker, Swarm, Kubernetes, Nomad, an HTTP endpoint, or a YAML file. Routes are picked up, added, and removed automatically.',
  },
  {
    number: '02',
    title: 'Automatic HTTPS',
    description:
      "Let's Encrypt provisioning and renewal, no intervention. Multi-domain SNI supported out of the box.",
  },
  {
    number: '03',
    title: 'HTTP/2 by default',
    description:
      'ALPN negotiates h2 on every TLS listener. No flag, no config — it just works.',
  },
  {
    number: '04',
    title: 'Hot reload',
    description:
      'REST API to create, update, delete entrypoints on the fly. Zero downtime, zero restart.',
  },
];

export default function FeatureSection() {
  return (
    <section className="features">
      <div className="container">
        <div className="features-header">
          <span className="features-eyebrow">Features</span>
          <h2 className="features-title">Built for ops who are tired of YAML.</h2>
          <p className="features-subtitle">
            Four things you should expect from a modern reverse proxy. None of them optional.
          </p>
        </div>
        <div className="features-grid">
          {FEATURES.map((f) => (
            <article key={f.title} className="feature-card">
              <div className="feature-card-label">{f.number}</div>
              <h3 className="feature-card-title">{f.title}</h3>
              <p className="feature-card-description">{f.description}</p>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
