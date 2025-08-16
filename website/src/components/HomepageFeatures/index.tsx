import React, {type ReactNode} from 'react';
import clsx from 'clsx';
import Heading from '@theme/Heading';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  Svg: React.ComponentType<React.ComponentProps<'svg'>>;
  description: React.ReactNode;
};

const FeatureList: FeatureItem[] = [
  {
    title: '🔍 Comprehensive Scanning',
    Svg: require('@site/static/img/undraw_docusaurus_mountain.svg').default,
    description: (
      <>
        Scan your entire AWS infrastructure including IAM policies, EC2 security groups, 
        and S3 bucket configurations to identify security vulnerabilities and misconfigurations.
      </>
    ),
  },
  {
    title: '🤖 AI-Powered Analysis',
    Svg: require('@site/static/img/undraw_docusaurus_tree.svg').default,
    description: (
      <>
        Leverage advanced AI analysis with Ollama to get detailed security reports, 
        remediation recommendations, and prioritized action items for your AWS environment.
      </>
    ),
  },
  {
    title: '📊 Interactive Dashboard',
    Svg: require('@site/static/img/undraw_docusaurus_react.svg').default,
    description: (
      <>
        Visualize your security posture through an intuitive Streamlit dashboard 
        with charts, metrics, and detailed findings for easy analysis and reporting.
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
