import React from 'react';
import { Typography, Card, Row, Col } from 'antd';
import {
  ApiOutlined,
  CodeOutlined,
  ThunderboltOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const highlights = [
  {
    icon: <SafetyCertificateOutlined style={{ fontSize: 36, color: '#2563eb' }} />,
    title: 'Built on Proven Engine',
    desc: 'Fork of dwisiswant0/apkleaks — scanning engine unchanged, adds an AI-native layer on top.',
  },
  {
    icon: <ApiOutlined style={{ fontSize: 36, color: '#7c3aed' }} />,
    title: 'MCP Server',
    desc: '12 tools, 4 resources, 4 prompts — native tool calls via stdio, no Bash subprocess.',
  },
  {
    icon: <CodeOutlined style={{ fontSize: 36, color: '#059669' }} />,
    title: 'Structured-JSON CLI',
    desc: '13 subcommands with deterministic JSON envelope — works from any shell-capable agent.',
  },
  {
    icon: <ThunderboltOutlined style={{ fontSize: 36, color: '#d97706' }} />,
    title: '9 Rev-Skills',
    desc: 'Auto-discovered on plugin install. Triggered by intent, chain seamlessly.',
  },
];

const HomePage: React.FC = () => (
  <>
    {/* Hero imported by the router layout */}
    {/* Highlights */}
    <section className="section">
      <Title level={2} style={{ textAlign: 'center', marginBottom: 48 }}>
        Why This Fork?
      </Title>
      <Row gutter={[24, 24]}>
        {highlights.map((h) => (
          <Col xs={24} sm={12} key={h.title}>
            <Card hoverable style={{ height: '100%', textAlign: 'center' }}>
              <div style={{ marginBottom: 16 }}>{h.icon}</div>
              <Title level={4}>{h.title}</Title>
              <Paragraph type="secondary">{h.desc}</Paragraph>
            </Card>
          </Col>
        ))}
      </Row>
    </section>

    {/* Quick demo */}
    <section className="section" style={{ background: '#ffffff', borderTop: '1px solid #e2e8f0', borderBottom: '1px solid #e2e8f0' }}>
      <Title level={3} style={{ textAlign: 'center', marginBottom: 32 }}>
        A Typical Agent Loop
      </Title>
      <pre
        style={{
          background: '#0f172a',
          color: '#e2e8f0',
          padding: '24px',
          borderRadius: 8,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace',
          fontSize: '0.85rem',
          lineHeight: 1.7,
          overflowX: 'auto',
          maxWidth: '100%',
        }}
      >
{`schema                          → learn the full API in one call
check   -f app.apk             → verify jadx + APK validity       (branch on ok)
info    -f app.apk             → package, permissions, SDK        (no decompile)
scan    -f app.apk -s high     → decompile + 95 rules, high+ only (branch on has_critical)
explain -c AWS_API_Key         → severity, impact & remediation   (per category)
search  -d <dir> -p <regex>    → grep decompiled source + context (verify a hit)`}
      </pre>
      <Paragraph style={{ textAlign: 'center', color: '#64748b', marginTop: 16 }}>
        Every step returns <Text code>ok</Text> + a stable <Text code>error_code</Text> — the agent never parses natural language to decide what to do next.
      </Paragraph>
    </section>

    {/* CTA */}
    <section className="section" style={{ textAlign: 'center' }}>
      <Title level={3}>Ready to get started?</Title>
      <Paragraph type="secondary" style={{ marginBottom: 24 }}>
        Install the plugin and scan your first APK in under a minute.
      </Paragraph>
      <a href="/apkleaks-skills/install" style={{ textDecoration: 'none' }}>
        <Text strong style={{ fontSize: '1.1rem', color: '#2563eb' }}>
          → Installation Guide
        </Text>
      </a>
    </section>
  </>
);

export default HomePage;
