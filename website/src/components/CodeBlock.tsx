import { useEffect, useRef } from 'react';
import Prism from 'prismjs';
import 'prismjs/components/prism-bash';
import 'prismjs/components/prism-yaml';
import 'prismjs/components/prism-json';
import 'prismjs/components/prism-toml';
import 'prismjs/components/prism-rust';
import CopyButton from './CopyButton';

interface CodeBlockProps {
  code: string;
  language: string;
  title?: string;
}

export default function CodeBlock({ code, language, title }: CodeBlockProps) {
  const ref = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (ref.current) {
      Prism.highlightElement(ref.current);
    }
  }, [code, language]);

  return (
    <div className="code-block">
      {title && (
        <div className="code-block-header">
          <div className="code-block-dots">
            <span /><span /><span />
          </div>
          <div className="code-block-title">{title}</div>
        </div>
      )}
      <CopyButton text={code} />
      <pre>
        <code ref={ref} className={`language-${language}`}>{code}</code>
      </pre>
    </div>
  );
}
