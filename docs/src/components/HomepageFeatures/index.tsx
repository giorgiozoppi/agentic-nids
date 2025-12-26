import type {ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'AI-Powered Detection',
    Svg: require('@site/static/img/undraw_docusaurus_mountain.svg').default,
    description: (
      <>
        Advanced machine learning with XGBoost classifiers and explainable AI
        using LLM-generated threat explanations from GPT-4 or Claude Opus for
        real-time network intrusion detection.
      </>
    ),
  },
  {
    title: 'Multi-Agent Architecture',
    Svg: require('@site/static/img/undraw_docusaurus_tree.svg').default,
    description: (
      <>
        Distributed agents communicating via NATS and A2A protocol for scalable,
        high-performance threat detection. Process 10,000+ flows per second with
        sub-10ms ML inference.
      </>
    ),
  },
  {
    title: 'Cloud-Native & Production-Ready',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        Kubernetes-ready with Helm charts, auto-scaling, and integrated monitoring.
        Includes PagerDuty alerting, InfluxDB storage, and Grafana dashboards for
        enterprise-grade security operations.
      </>
    ),
  },
];

function Feature({title, Svg, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <Svg className={styles.featureSvg} role="img" />
      </div>
      <div className="text--center padding-horiz--md">
        <Heading as="h3">{title}</Heading>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): ReactNode {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
