import React from 'react';
import { Typography, Card, Row, Col, Statistic, Divider } from 'antd';
import {
  BugOutlined,
  ApiOutlined,
  CodeOutlined,
  ThunderboltOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const categories = [
  'Cloud providers',
  'AI / LLM',
  'Messaging',
  'Payments',
  'DevOps',
  'Monitoring',
  'CDN',
  'Hosting',
  'Identity',
  'Private keys',
  'Android-specific',
  'Generic',
];

const contractFeatures = [
  { icon: <SafetyCertificateOutlined />, label: 'ok flag + stable error_code', desc: 'Single boolean for branching; stable machine-matchable codes (FILE_NOT_FOUND, INVALID_APK, NO_FINDINGS…)' },
  { icon: <ApiOutlined />, label: 'schema self-discovery', desc: 'One call returns all subcommands, parameters & return structures — agent learns the full API without reading source' },
  { icon: <BugOutlined />, label: 'has_critical triage', desc: 'Findings pre-sorted critical→info; flag for one-branch triage; filter with -s critical / severity parameter' },
];

const FeaturesPage: React.FC = () => (
  <section className="section">
    <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
      Feature Tree at a Glance
    </Title>
    <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 32 }}>
      A fork of upstream APKLeaks, re-architected as an AI-native toolkit. Rendered by
      <Text code> tools/feature_tree.py</Text> (pure stdlib, no Mermaid/Graphviz).
    </Paragraph>

    {/* Feature tree SVG */}
    <Card style={{ textAlign: 'center', margin: '0 auto 48px', maxWidth: 900 }}>
      <img
        src="https://raw.githubusercontent.com/android-security-engineer/apkleaks-skills/master/docs/feature-tree.svg"
        alt="APKLeaks for AI Agents — feature tree"
        style={{ maxWidth: '100%', height: 'auto' }}
      />
    </Card>

    <Divider />

    {/* Detection coverage stats */}
    <Title level={3}>Detection Coverage</Title>
    <Row gutter={[24, 24]} style={{ marginBottom: 32 }}>
      <Col xs={12} sm={6}>
        <Statistic title="Regex Patterns" value={95} prefix={<BugOutlined />} suffix="+" />
      </Col>
      <Col xs={12} sm={6}>
        <Statistic title="Categories" value={12} prefix={<CodeOutlined />} />
      </Col>
      <Col xs={12} sm={6}>
        <Statistic title="MCP Tools" value={12} prefix={<ApiOutlined />} />
      </Col>
      <Col xs={12} sm={6}>
        <Statistic title="CLI Subcommands" value={13} prefix={<ThunderboltOutlined />} />
      </Col>
    </Row>
    <Row gutter={[8, 8]}>
      {categories.map((c) => (
        <Col key={c}>
          <Text code style={{ fontSize: '0.85rem' }}>{c}</Text>
        </Col>
      ))}
    </Row>

    <Divider />

    {/* Agent contract */}
    <Title level={3}>Agent Contract</Title>
    <Paragraph type="secondary" style={{ marginBottom: 24 }}>
      Every response follows the same predictable structure — deterministic, machine-readable, no prose parsing needed.
    </Paragraph>
    <Row gutter={[24, 24]}>
      {contractFeatures.map((f) => (
        <Col xs={24} md={8} key={f.label}>
          <Card hoverable style={{ height: '100%' }}>
            <div style={{ fontSize: 24, color: '#2563eb', marginBottom: 12 }}>{f.icon}</div>
            <Title level={5}>{f.label}</Title>
            <Paragraph type="secondary">{f.desc}</Paragraph>
          </Card>
        </Col>
      ))}
    </Row>

    {/* Response envelope */}
    <Divider />
    <Title level={4}>Response Envelope</Title>
    <Paragraph type="secondary">Every subcommand and tool returns one of:</Paragraph>
    <Row gutter={[24, 24]}>
      <Col xs={24} md={12}>
        <Card style={{ background: '#f0fdf4', borderColor: '#86efac' }}>
          <Text strong style={{ color: '#166534' }}>✓ Success</Text>
          <pre style={{ background: '#0f172a', color: '#e2e8f0', padding: 12, borderRadius: 6, fontSize: '0.8rem', marginTop: 8 }}>
{`{"ok": true, "timestamp": "ISO-8601",
 "duration_ms": 123, "data": { /* result */ }}`}
          </pre>
        </Card>
      </Col>
      <Col xs={24} md={12}>
        <Card style={{ background: '#fef2f2', borderColor: '#fca5a5' }}>
          <Text strong style={{ color: '#991b1b' }}>✗ Error</Text>
          <pre style={{ background: '#0f172a', color: '#e2e8f0', padding: 12, borderRadius: 6, fontSize: '0.8rem', marginTop: 8 }}>
{`{"ok": false, "timestamp": "ISO-8601",
 "error": "human-readable text",
 "error_code": "FILE_NOT_FOUND"}`}
          </pre>
        </Card>
      </Col>
    </Row>
  </section>
);

export default FeaturesPage;
