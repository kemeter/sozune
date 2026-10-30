import { Link } from 'react-router-dom';

interface Capability {
  tag: string;
  title: string;
  description: string;
  demo?: { warn: string; label: string; hint: string };
  link?: { to: string; label: string };
}

const CAPABILITIES: Capability[] = [
  {
    tag: 'follow',
    title: 'Live route updates',
    description:
      'Sōzune follows each platform, through its events or by polling, and applies every change to the running Sōzu workers. A deploy, a scale or a stopped container reroutes traffic without restarting the proxy.',
  },
  {
    tag: 'secure',
    title: 'Managed HTTPS',
    description:
      "Turn on ACME and Sōzune gets certificates from Let's Encrypt for the hosts you route, over HTTP-01, TLS-ALPN-01 or DNS-01, wildcards included, and renews them. Or bring your own.",
  },
  {
    tag: 'diagnose',
    title: 'It tells you why',
    description:
      'A mistyped label is reported with a did-you-mean, and `sozune validate` checks your setup before you deploy. `sozune route` shows which route a request would take, and why the others would not.',
    demo: {
      warn: '⚠ W013',
      label: "unknown label 'sozune.http.web.hsot', ignored",
      hint: '→ did you mean `sozune.http.web.host`?',
    },
  },
  {
    tag: 'extend',
    title: 'More than HTTP routing',
    description:
      'Rate limits, auth, header rules and WASM plugins as middlewares, TCP and UDP listeners, and the Kubernetes Gateway API.',
    link: { to: '/documentation/getting-started/migrating-from-traefik', label: 'Coming from Traefik? →' },
  },
];

// Renders `backticked` spans of a description as inline code.
function withCode(text: string) {
  return text
    .split('`')
    .map((part, i) => (i % 2 === 1 ? <code key={i}>{part}</code> : part));
}

export default function FeatureSection() {
  return (
    <section className="features">
      <div className="container">
        <div className="features-header">
          <span className="features-eyebrow">What Sōzune does for you</span>
          <h2 className="features-title">Less to wire up by hand.</h2>
        </div>
        <div className="features-grid">
          {CAPABILITIES.map((c) => (
            <article key={c.tag} className="feature-card">
              <div className="feature-card-label">{c.tag}</div>
              <h3 className="feature-card-title">{c.title}</h3>
              <p className="feature-card-description">{withCode(c.description)}</p>
              {c.demo && (
                <div className="feature-card-demo">
                  <span className="demo-warn">{c.demo.warn}</span> {c.demo.label}
                  {'\n'}
                  <span className="demo-hint">{`   ${c.demo.hint}`}</span>
                </div>
              )}
              {c.link && (
                <Link to={c.link.to} className="feature-card-link">
                  {c.link.label}
                </Link>
              )}
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
