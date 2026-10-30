import Hero from '@/components/Hero';
import ProxyDiagram from '@/components/ProxyDiagram';
import PlatformShowcase from '@/components/PlatformShowcase';
import FeatureSection from '@/components/FeatureSection';

const description =
  'A reverse proxy built on Sōzu. Declare routes alongside your services on Docker, Podman, Swarm, Kubernetes, Nomad, Consul or Ring: Sōzune discovers their backends, updates routing as they change, and can manage HTTPS certificates with ACME.';

export const meta = {
  title: 'Sōzune — Routes that follow your services',
  description,
  canonical: 'https://sozune.kemeter.io/',
  og: {
    title: 'Sōzune — Routes that follow your services',
    description,
    type: 'website',
    url: 'https://sozune.kemeter.io/',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Sōzune — Routes that follow your services',
    description,
  },
};

export default function HomePage() {
  return (
    <>
      <Hero />
      <ProxyDiagram />
      <PlatformShowcase />
      <FeatureSection />
    </>
  );
}
