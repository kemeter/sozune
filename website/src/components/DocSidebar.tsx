import { NavLink } from 'react-router-dom';
import { getAllDocs, docToUrl, humanize } from '@/lib/docs';

interface SidebarLink {
  to: string;
  label: string;
}

interface SidebarSection {
  title: string;
  links: SidebarLink[];
}

function buildSections(): SidebarSection[] {
  const rootLinks: SidebarLink[] = [];
  const sectionsByFolder = new Map<string, SidebarLink[]>();

  for (const doc of getAllDocs()) {
    const link: SidebarLink = { to: docToUrl(doc.slug), label: doc.title };
    if (doc.segments.length <= 1) {
      rootLinks.push(link);
    } else {
      const folder = doc.segments[0];
      if (!sectionsByFolder.has(folder)) {
        sectionsByFolder.set(folder, []);
      }
      sectionsByFolder.get(folder)!.push(link);
    }
  }

  const sections: SidebarSection[] = [];
  if (rootLinks.length > 0) {
    sections.push({ title: 'Introduction', links: rootLinks });
  }
  for (const [folder, links] of sectionsByFolder) {
    sections.push({ title: humanize(folder), links });
  }
  return sections;
}

const sections = buildSections();

export default function DocSidebar() {
  return (
    <aside className="doc-sidebar">
      {sections.map((section) => (
        <div key={section.title} className="doc-sidebar-section">
          <div className="doc-sidebar-section-title">{section.title}</div>
          {section.links.map((link) => (
            <NavLink
              key={link.to}
              to={link.to}
              end={link.to === '/documentation'}
              className={({ isActive }) =>
                `doc-sidebar-link${isActive ? ' active' : ''}`
              }
            >
              {link.label}
            </NavLink>
          ))}
        </div>
      ))}
    </aside>
  );
}
