import { useLocation } from 'react-router-dom';
import MarkdownPage from '@/components/MarkdownPage';
import { getDoc } from '@/lib/docs';

const NOT_FOUND = {
  content: '# Page not found\n\nThis documentation page does not exist.',
  title: 'Page not found',
  description: '',
};

export const meta = (url: string, params: { path?: string }) => {
  const slug = params.path ?? '';
  const page = getDoc(slug);
  const title = page ? `${page.title} — Sozune Docs` : 'Documentation — Sozune';
  const description = page?.description || 'Sozune documentation.';
  const canonical = `https://sozune.kemeter.io${url}`;
  return {
    title,
    description,
    canonical,
    og: { title, description, type: 'article', url: canonical },
    twitter: { card: 'summary', title, description },
  };
};

export default function DocPage() {
  const { pathname } = useLocation();
  const slug = pathname.replace(/^\/documentation\/?/, '').replace(/\/$/, '');
  const page = getDoc(slug) ?? NOT_FOUND;

  return <MarkdownPage content={page.content} title={`${page.title} — Sozune Docs`} />;
}
