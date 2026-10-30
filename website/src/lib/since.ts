import cargo from '../../../Cargo.toml';

// The version being developed, `0.16` for `0.16.0-dev`: what it marks is
// not released yet.
const devVersion = /^version\s*=\s*"(\d+)\.(\d+)\.\d+-dev"/m.exec(cargo);
const UNRELEASED = devVersion ? `${devVersion[1]}.${devVersion[2]}` : null;

const SINCE_LINE = /^\s*Since (\d+\.\d+)\s*$/;
const SINCE_INLINE = /\(since (\d+\.\d+)\)/g;

interface HastNode {
  type: string;
  tagName?: string;
  value?: string;
  properties?: Record<string, unknown>;
  children?: HastNode[];
}

function textOf(node: HastNode): string {
  if (node.type === 'text') return node.value ?? '';
  return (node.children ?? []).map(textOf).join('');
}

function badge(version: string, inline: boolean): HastNode {
  const unreleased = version === UNRELEASED;
  const classes = ['since'];
  if (inline) classes.push('since-inline');
  if (unreleased) classes.push('since-unreleased');
  const label = inline ? version : `Since ${version}${unreleased ? ' · unreleased' : ''}`;
  return {
    type: 'element',
    tagName: 'span',
    properties: {
      className: classes,
      title: unreleased ? `Coming in ${version}, not released yet` : `Available since ${version}`,
    },
    children: [{ type: 'text', value: label }],
  };
}

/// `> Since 0.15` becomes a version badge, and `(since 0.15)` in running
/// text a small one. Both stay plain markdown on GitHub.
function transform(node: HastNode): void {
  const children = node.children;
  if (!children) return;
  for (let i = 0; i < children.length; i++) {
    const child = children[i];
    if (child.type === 'element' && child.tagName === 'blockquote') {
      const match = SINCE_LINE.exec(textOf(child));
      if (match) {
        children[i] = {
          type: 'element',
          tagName: 'p',
          properties: { className: ['doc-since'] },
          children: [badge(match[1], false)],
        };
        continue;
      }
    }
    if (child.type === 'element' && (child.tagName === 'code' || child.tagName === 'pre')) {
      continue;
    }
    if (child.type === 'text' && child.value && SINCE_INLINE.test(child.value)) {
      SINCE_INLINE.lastIndex = 0;
      const parts: HastNode[] = [];
      let last = 0;
      for (const m of child.value.matchAll(SINCE_INLINE)) {
        const start = m.index ?? 0;
        const before = child.value.slice(last, start).replace(/\s+$/, ' ');
        if (before) parts.push({ type: 'text', value: before });
        parts.push(badge(m[1], true));
        last = start + m[0].length;
      }
      const rest = child.value.slice(last);
      if (rest) parts.push({ type: 'text', value: rest });
      children.splice(i, 1, ...parts);
      i += parts.length - 1;
      continue;
    }
    transform(child);
  }
}

export default function rehypeSince() {
  return (tree: HastNode) => transform(tree);
}
