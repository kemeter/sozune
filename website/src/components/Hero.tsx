import { Link } from 'react-router-dom';

export default function Hero() {
  return (
    <section className="hero">
      <div className="container hero-inner">
        <h1 className="hero-title">
          Routes that follow
          <br />
          <span className="hero-title-accent">your services.</span>
        </h1>
        <p className="hero-subtitle">
          Declare routes alongside your services. Sōzune discovers backends and keeps
          routing up to date as your services change. Sōzune automatically manages
          HTTPS certificates with ACME.
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
