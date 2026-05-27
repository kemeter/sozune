interface Capability {
  tag: string;
  title: string;
  description: string;
  demo?: { warn: string; label: string; hint: string };
}

const CAPABILITIES: Capability[] = [
  {
    tag: 'discover',
    title: 'Real-time service discovery',
    description:
      "Watches each platform's events and keeps the routing table in sync as services come and go. Nothing to reload by hand.",
  },
  {
    tag: 'secure',
    title: 'Automatic HTTPS',
    description:
      "Let's Encrypt over HTTP-01 and DNS-01, wildcards included. Certificates provisioned and renewed without you touching a file.",
  },
  {
    tag: 'diagnose',
    title: 'It tells you why',
    description:
      'A typo’d label or a shadowed route never fails silently. Validate before deploy, or read the reason straight off the failing request.',
    demo: {
      warn: '⚠ W013',
      label: 'unknown label "sozune.http.web.hsot"',
      hint: '→ did you mean `sozune.http.web.host`?',
    },
  },
  {
    tag: 'operate',
    title: 'Labels, API & dashboard',
    description:
      'Configure routes where your services live, drive them over a REST API, and watch the live state from the built-in dashboard.',
  },
];

export default function FeatureSection() {
  return (
    <section className="features">
      <div className="container">
        <div className="features-header">
          <span className="features-eyebrow">What Sōzune does for you</span>
          <h2 className="features-title">Four things, handled.</h2>
        </div>
        <div className="features-grid">
          {CAPABILITIES.map((c) => (
            <article key={c.tag} className="feature-card">
              <div className="feature-card-label">{c.tag}</div>
              <h3 className="feature-card-title">{c.title}</h3>
              <p className="feature-card-description">{c.description}</p>
              {c.demo && (
                <div className="feature-card-demo">
                  <span className="demo-warn">{c.demo.warn}</span> {c.demo.label}
                  {'\n'}
                  <span className="demo-hint">{`   ${c.demo.hint}`}</span>
                </div>
              )}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
