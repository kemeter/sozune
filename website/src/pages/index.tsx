import Hero from '@/components/Hero';
import FeatureSection from '@/components/FeatureSection';

const description =
  'The modern reverse proxy, without the painful config. Service discovery for Docker, Swarm, Kubernetes and Nomad, automatic HTTPS, HTTP/2 by default, hot reload through REST API.';

export const meta = {
  title: 'Sozune — The modern reverse proxy',
  description,
  canonical: 'https://sozune.kemeter.io/',
  og: {
    title: 'Sozune — The modern reverse proxy',
    description,
    type: 'website',
    url: 'https://sozune.kemeter.io/',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'Sozune — The modern reverse proxy',
    description,
  },
};

export default function HomePage() {
  return (
    <>
      <Hero />
      <FeatureSection />
    </>
  );
}
