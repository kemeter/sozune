const fs = require('node:fs');
const path = require('node:path');

function walkMdFiles(dir, prefix = '') {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      out.push(...walkMdFiles(abs, rel));
    } else if (entry.isFile() && entry.name.endsWith('.md') && entry.name.toLowerCase() !== 'readme.md') {
      out.push(rel.replace(/\.md$/, '').replace(/\/?index$/, ''));
    }
  }
  return out;
}

module.exports = {
  reactStrictMode: true,
  server: {
    port: 3001,
  },
  routes: [
    {
      source: '/documentation/[...path]',
      paths: () => {
        const docsDir = path.resolve(__dirname, '../documentation');
        if (!fs.existsSync(docsDir)) {
          return [];
        }
        return walkMdFiles(docsDir).map((slug) =>
          slug === '' ? '/documentation' : `/documentation/${slug}`
        );
      },
    },
  ],
  head: {
    defaultTitle: 'Sozune — The modern reverse proxy',
    titleTemplate: '%s | Sozune',
    meta: [
      { name: 'description', content: 'The modern reverse proxy, without the painful config. Docker auto-discovery, automatic HTTPS, HTTP/2 by default, hot reload through REST API.' },
      { name: 'viewport', content: 'width=device-width, initial-scale=1' },
      { property: 'og:title', content: 'Sozune — The modern reverse proxy' },
      { property: 'og:description', content: 'Docker auto-discovery, automatic HTTPS, HTTP/2 by default, hot reload through REST API.' },
      { property: 'og:type', content: 'website' },
    ],
  },
};
