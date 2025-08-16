import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

/**
 * Creating a sidebar enables you to:
 - create an ordered group of docs
 - render a sidebar for each doc of that group
 - provide next/previous navigation

 The sidebars can be generated from the filesystem, or explicitly defined here.

 Create as many sidebars as you want.
 */
const sidebars: SidebarsConfig = {
  // CloudSecVision Documentation Sidebar
  tutorialSidebar: [
    'intro',
    'getting-started',
    {
      type: 'category',
      label: '🔍 Security Scanners',
      collapsed: false,
      items: [
        'scanners/overview',
        'scanners/iam-scanner',
        'scanners/ec2-scanner',
        'scanners/s3-scanner',
      ],
    },
    {
      type: 'category',
      label: '📊 Dashboard',
      collapsed: false,
      items: [
        'dashboard/overview',
      ],
    },
    {
      type: 'category',
      label: '🤖 AI Analysis',
      collapsed: false,
      items: [
        'ai-analysis/overview',
      ],
    },
    {
      type: 'category',
      label: '📚 Additional Resources',
      collapsed: true,
      items: [
        'faq',
        'troubleshooting',
        'best-practices',
        'contributing',
      ],
    },
  ],
};

export default sidebars;
