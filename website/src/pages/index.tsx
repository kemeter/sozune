import Hero from '@/components/Hero';
import PlatformShowcase from '@/components/PlatformShowcase';
import FeatureSection from '@/components/FeatureSection';

const description =
  'The reverse proxy that configures itself. Sōzune discovers your services across Docker, Kubernetes, Nomad and Consul, secures them with automatic HTTPS, and keeps the routing table in sync.';

export const meta = {
  title: 'Sōzune — The reverse proxy that configures itself',
  description,
  canonical: 'https://sozune.kemeter.io/',
  og: {
    title: 'Sōzune — The reverse proxy that configures itself',
    description,
    type: 'website',
    url: 'https://sozune.kemeter.io/',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Sōzune — The reverse proxy that configures itself',
    description,
  },
};

export default function HomePage() {
  return (
    <>
      <Hero />
      <PlatformShowcase />
      <FeatureSection />
    </>
  );
}
