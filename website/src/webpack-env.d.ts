interface RequireContext {
  keys(): string[];
  (id: string): unknown;
  <T>(id: string): T;
  resolve(id: string): string;
  id: string;
}

interface NodeRequire {
  context(
    directory: string,
    useSubdirectories?: boolean,
    regExp?: RegExp,
    mode?: 'sync' | 'lazy' | 'lazy-once' | 'eager' | 'weak'
  ): RequireContext;
}

declare module '*.md' {
  const content: string;
  export default content;
}
