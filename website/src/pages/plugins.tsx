import { Link } from 'react-router-dom';
import manifest from '@/data/plugins.json';

const description =
  'Browse plugins for Sozune. WASM middleware built on the http-wasm ABI, plus every plugin from the Traefik catalog runs unchanged.';

export const meta = {
  title: 'Plugins — Sozune',
  description,
  canonical: 'https://sozune.kemeter.io/plugins',
  og: {
    title: 'Plugins — Sozune',
    description,
    type: 'website',
    url: 'https://sozune.kemeter.io/plugins',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Plugins — Sozune',
    description,
  },
};

interface Plugin {
  name: string;
  version: string;
  summary: string;
  author: string;
  tags: string[];
  abi: string;
  repo: string;
  wasm: string | null;
  example: Record<string, unknown>;
}

const plugins = (manifest.plugins as Plugin[]) ?? [];

export default function PluginsPage() {
  return (
    <section className="help">
      <div className="container">
        <div className="help-head">
          <span className="help-eyebrow">Sozune</span>
          <h1>Plugins</h1>
          <p>
            Extend Sozune with sandboxed WASM middleware — geo-blocking,
            analytics, bot filtering — built on the{' '}
            <a href="https://http-wasm.io" target="_blank" rel="noreferrer">
              http-wasm
            </a>{' '}
            ABI. Want yours listed? See the{' '}
            <Link to="/documentation/middleware/wasm-plugins">
              WASM plugins guide
            </Link>
            .
          </p>
        </div>

        <div className="help-grid">
          {plugins.map((plugin) => (
            <article className="help-card" key={plugin.name}>
              <h3>{plugin.name}</h3>
              <p>{plugin.summary}</p>
              <div className="plugin-tags">
                {plugin.tags.map((tag) => (
                  <span className="plugin-tag" key={tag}>
                    {tag}
                  </span>
                ))}
              </div>
              <div className="help-card-actions">
                <a
                  className="help-lnk"
                  href={plugin.repo}
                  target="_blank"
                  rel="noreferrer"
                >
                  View source →
                </a>
              </div>
            </article>
          ))}

          <article className="help-card">
            <h3>More plugins</h3>
            <p>
              Sozune targets the same http-wasm ABI as Traefik, so any
              self-contained guest from the Traefik catalog runs here unchanged.
            </p>
            <div className="help-card-actions">
              <a
                className="help-lnk"
                href="https://plugins.traefik.io/plugins"
                target="_blank"
                rel="noreferrer"
              >
                Browse the Traefik catalog →
              </a>
            </div>
          </article>
        </div>
      </div>
    </section>
  );
}
