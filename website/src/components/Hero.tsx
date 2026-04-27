import { Link } from 'react-router-dom';
import CodeBlock from './CodeBlock';

const HERO_SNIPPET = `services:
  whoami:
    image: traefik/whoami
    labels:
      - "sozune.enable=true"
      - "sozune.http.app.host=app.example.com"
      - "sozune.http.app.tls=true"`;

export default function Hero() {
  return (
    <section className="hero">
      <div className="container hero-inner">
        <div className="hero-eyebrow">
          <strong>sozune</strong> — built on Sōzu
        </div>
        <h1 className="hero-title">
          The modern reverse proxy,
          <br />
          <span className="hero-title-accent">without the painful config.</span>
        </h1>
        <p className="hero-subtitle">
          Auto-discovery from Docker labels. Automatic HTTPS with Let&apos;s Encrypt.
          HTTP/2 by default. Hot reload through a REST API.
        </p>
        <div className="hero-actions">
          <Link to="/documentation/quick-start" className="btn btn-primary">
            Quick start
          </Link>
          <a
            href="https://github.com/kemeter/sozune"
            className="btn btn-secondary"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
        </div>
        <div className="hero-code">
          <CodeBlock code={HERO_SNIPPET} language="yaml" title="docker-compose.yml" />
        </div>
      </div>
    </section>
  );
}
