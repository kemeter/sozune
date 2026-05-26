export interface DocEntry {
  slug: string;
  content: string;
  title: string;
  description: string;
  segments: string[];
}

function extractTitle(markdown: string): string {
  for (const rawLine of markdown.split('\n')) {
    const line = rawLine.trim();
    if (line.startsWith('# ')) {
      return line.slice(2).trim();
    }
  }
  return '';
}

function extractDescription(markdown: string): string {
  let pastTitle = false;
  const buffer: string[] = [];
  for (const rawLine of markdown.split('\n')) {
    const line = rawLine.trim();
    if (!pastTitle) {
      if (line.startsWith('# ')) {
        pastTitle = true;
      }
      continue;
    }
    if (!line) {
      if (buffer.length > 0) break;
      continue;
    }
    if (line.startsWith('#') || line.startsWith('```') || line.startsWith('|') || line.startsWith('- ') || line.startsWith('* ')) {
      if (buffer.length > 0) break;
      continue;
    }
    buffer.push(line);
  }
  const text = buffer.join(' ').replace(/`([^`]+)`/g, '$1').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1');
  if (text.length <= 200) return text;
  return text.slice(0, 197).replace(/\s+\S*$/, '') + '…';
}

function humanize(segment: string): string {
  return segment
    .split(/[-_]/)
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ');
}

const ctx = require.context('@docs', true, /\.md$/, 'sync');

// Folder display order in the sidebar. Folders not listed here appear after,
// in alphabetical order.
const FOLDER_ORDER = [
  'getting-started',
  'routing',
  'providers',
  'middleware',
  'tls',
  'configuration',
  'advanced',
];

// Per-folder page order. Pages not listed here fall back to alphabetical.
const PAGE_ORDER: Record<string, string[]> = {
  'getting-started': ['installation', 'quick-start'],
  routing: ['hostnames', 'path-matching', 'load-balancing', 'tcp'],
  providers: ['docker', 'swarm', 'http'],
  middleware: [
    'auth',
    'headers',
    'rate-limit',
    'redirects',
    'strip-prefix',
    'compress',
    'backend-timeout',
    'wasm-plugins',
  ],
  tls: ['overview', 'acme'],
  configuration: ['overview', 'api', 'dashboard'],
  advanced: ['debugging', 'access-logs', 'health-checks', 'websocket'],
};

function pageOrderIndex(segments: string[]): number {
  if (segments.length < 2) return -1;
  const folder = segments[0];
  const page = segments[segments.length - 1];
  const order = PAGE_ORDER[folder];
  if (!order) return Number.MAX_SAFE_INTEGER;
  const idx = order.indexOf(page);
  return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
}

function folderOrderIndex(segments: string[]): number {
  if (segments.length === 0) return -1;
  const folder = segments[0];
  const idx = FOLDER_ORDER.indexOf(folder);
  return idx === -1 ? Number.MAX_SAFE_INTEGER : idx;
}

const docs: DocEntry[] = ctx.keys()
  .filter((key) => !/(^|\/)README\.md$/i.test(key))
  .map((key) => {
    const relPath = key.replace(/^\.\//, '').replace(/\.md$/, '');
    const slug = relPath.replace(/\/?index$/, '');
    const segments = slug.split('/').filter(Boolean);
    const content = ctx<string>(key);
    const title = extractTitle(content) || humanize(segments[segments.length - 1] || 'Overview');
    const description = extractDescription(content);
    return { slug, content, title, description, segments };
  })
  .sort((a, b) => {
    // Root pages first
    if (a.segments.length <= 1 && b.segments.length > 1) return -1;
    if (a.segments.length > 1 && b.segments.length <= 1) return 1;

    // Then by folder order
    const folderDiff = folderOrderIndex(a.segments) - folderOrderIndex(b.segments);
    if (folderDiff !== 0) return folderDiff;

    // Then by page order within the folder
    const pageDiff = pageOrderIndex(a.segments) - pageOrderIndex(b.segments);
    if (pageDiff !== 0) return pageDiff;

    // Final tiebreaker: alphabetical
    return a.slug.localeCompare(b.slug);
  });

const bySlug = new Map(docs.map((doc) => [doc.slug, doc]));

export function getDoc(slug: string): DocEntry | undefined {
  return bySlug.get(slug);
}

export function getAllDocs(): DocEntry[] {
  return docs;
}

export function docToUrl(slug: string): string {
  return slug === '' ? '/documentation' : `/documentation/${slug}`;
}

export { humanize };
