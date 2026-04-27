export default function Footer() {
  return (
    <footer className="footer">
      <div className="container footer-inner">
        <div className="footer-brand">
          <strong>sozune</strong> — built on{' '}
          <a href="https://github.com/sozu-proxy/sozu" target="_blank" rel="noreferrer">Sōzu</a>
        </div>
        <div className="footer-links">
          <a href="/documentation">Documentation</a>
          <a href="https://github.com/kemeter/sozune" target="_blank" rel="noreferrer">GitHub</a>
          <a href="https://github.com/kemeter/sozune/issues" target="_blank" rel="noreferrer">Issues</a>
        </div>
      </div>
    </footer>
  );
}
