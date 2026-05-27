import { Link } from 'react-router-dom';

export default function Hero() {
  return (
    <section className="hero">
      <div className="container hero-inner">
        <div className="hero-eyebrow">discovery · routing · TLS · diagnostics</div>
        <h1 className="hero-title">
          The reverse proxy that
          <br />
          <span className="hero-title-accent">configures itself.</span>
        </h1>
        <p className="hero-subtitle">
          Declare routing where your services already live. Sōzune discovers them,
          secures them with automatic HTTPS, and keeps the routing table in sync.
        </p>
        <div className="hero-actions">
          <Link to="/documentation/getting-started/quick-start" className="btn btn-primary">
            Quick start
          </Link>
          <Link to="/documentation" className="btn btn-secondary">
            Documentation →
          </Link>
        </div>
      </div>
    </section>
  );
}
