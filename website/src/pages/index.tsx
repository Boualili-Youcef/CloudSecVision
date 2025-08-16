import React from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import HomepageFeatures from '@site/src/components/HomepageFeatures';
import type {JSX} from 'react';

import styles from './index.module.css';

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <h1 className="hero__title">CloudSecVision</h1>
        <p className="hero__subtitle">
          Scanner de sécurité AWS avec analyse IA - Détectez et analysez les vulnérabilités dans votre infrastructure cloud
        </p>
        <div className={styles.buttons}>
          <Link
            className="button button--secondary button--lg"
            to="/docs/intro">
            Commencer - 5min ⏱️
          </Link>
          <Link
            className="button button--primary button--lg margin-left--md"
            to="/docs/getting-started">
            Guide d'installation
          </Link>
        </div>
      </div>
    </header>
  );
}

export default function Home(): JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title}`}
      description="Scanner de sécurité AWS avec analyse IA pour détecter les vulnérabilités">
      <HomepageHeader />
      <main>
        <HomepageFeatures />
      </main>
    </Layout>
  );
}