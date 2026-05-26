import { Link } from 'react-router-dom';

export default function Header() {
  return (
    <header className="header">
      <div className="container header-inner">
        <Link to="/" className="header-logo">
          <span className="header-logo-mark" />
          <span>sozune</span>
        </Link>
        <nav className="header-nav">
          <Link to="/documentation">Documentation</Link>
          <Link to="/plugins">Plugins</Link>
          <Link to="/help">Help</Link>
          <a
            href="https://github.com/kemeter/sozune"
            className="header-cta"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
        </nav>
      </div>
    </header>
  );
}
