import { useEffect, useRef, useState } from 'react';
import Prism from 'prismjs';
import 'prismjs/components/prism-yaml';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-hcl';

interface Platform {
  id: string;
  label: string;
  language: string;
  code: string;
}

const PLATFORMS: Platform[] = [
  {
    id: 'docker',
    label: 'Docker',
    language: 'yaml',
    code: `# docker-compose.yml
labels:
  - "sozune.enable=true"
  - "sozune.http.web.host=api.example.com"
  - "sozune.http.web.tls=true"`,
  },
  {
    id: 'nomad',
    label: 'Nomad',
    language: 'hcl',
    code: `# api.nomad — service block
service {
  name = "api"
  port = "http"
  tags = [
    "sozune.enable=true",
    "sozune.http.web.host=api.example.com",
  ]
}`,
  },
  {
    id: 'kubernetes',
    label: 'Kubernetes',
    language: 'yaml',
    code: `# ingress.yaml
metadata:
  annotations:
    sozune.http.web.host: api.example.com
    sozune.http.web.tls: "true"`,
  },
  {
    id: 'consul',
    label: 'Consul',
    language: 'json',
    code: `{
  "Name": "api",
  "Port": 8080,
  "Tags": [
    "sozune.enable=true",
    "sozune.http.web.host=api.example.com"
  ]
}`,
  },
];

export default function PlatformShowcase() {
  const [active, setActive] = useState(PLATFORMS[0].id);
  const codeRef = useRef<HTMLElement | null>(null);
  const current = PLATFORMS.find((p) => p.id === active) ?? PLATFORMS[0];

  useEffect(() => {
    if (codeRef.current) {
      Prism.highlightElement(codeRef.current);
    }
  }, [active]);

  return (
    <section className="showcase">
      <div className="container">
        <div className="showcase-term">
          <div className="showcase-chrome">
            <div className="showcase-lights">
              <span /><span /><span />
            </div>
            <div className="showcase-tabs" role="tablist">
              {PLATFORMS.map((p) => (
                <button
                  key={p.id}
                  role="tab"
                  aria-selected={p.id === active}
                  className={`showcase-tab${p.id === active ? ' active' : ''}`}
                  onClick={() => setActive(p.id)}
                >
                  {p.label}
                </button>
              ))}
            </div>
          </div>
          <pre className="showcase-pre">
            <code ref={codeRef} className={`language-${current.language}`}>
              {current.code}
            </code>
          </pre>
        </div>
        <p className="showcase-caption">
          Same <strong>sozune.*</strong> keys. Move the service, the routing moves with it.
        </p>
      </div>
    </section>
  );
}
