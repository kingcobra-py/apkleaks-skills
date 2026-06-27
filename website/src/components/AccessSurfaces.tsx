import React from 'react';
import { Typography, Row, Col, Card, Tag } from 'antd';
import {
  ApiOutlined,
  CodeOutlined,
  ThunderboltOutlined,
  SafetyCertificateOutlined,
  SearchOutlined,
  ToolOutlined,
} from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const surfaces = [
  {
    icon: <ApiOutlined style={{ fontSize: 32, color: '#2563eb' }} />,
    title: 'MCP Server',
    desc: '12 tools · 4 resources · 4 prompts — native tool calls via Model Context Protocol (stdio). No Bash subprocess, no stdout parsing.',
    tags: ['Claude Code', 'MCP'],
    color: '#2563eb',
  },
  {
    icon: <CodeOutlined style={{ fontSize: 32, color: '#7c3aed' }} />,
    title: 'Structured-JSON CLI',
    desc: '13 subcommands, deterministic JSON envelope. Every call returns { ok, data/error_code } — zero-config, works from any shell.',
    tags: ['Any Agent', 'Bash'],
    color: '#7c3aed',
  },
  {
    icon: <ThunderboltOutlined style={{ fontSize: 32, color: '#059669' }} />,
    title: 'Claude Code Skills',
    desc: '9 rev-* skills auto-discovered on plugin install. Triggered by intent (e.g. /rev-apkleaks), chain seamlessly.',
    tags: ['9 Skills', 'Plugin'],
    color: '#059669',
  },
];

const capabilities = [
  { icon: <SafetyCertificateOutlined />, label: 'check / info', desc: 'Verify prerequisites & APK metadata without decompiling' },
  { icon: <SearchOutlined />, label: 'scan — severity-graded', desc: 'Decompile + 95+ regex rules, findings sorted critical → info' },
  { icon: <CodeOutlined />, label: 'decompile / search', desc: 'Java source + regex search with file-type filter & context' },
  { icon: <ToolOutlined />, label: 'explain — impact + fix', desc: 'Per-category severity, impact & remediation for every finding' },
  { icon: <ToolOutlined />, label: 'rule add / test / remove', desc: 'Runtime rule extension — add custom patterns without restart' },
];

const AccessSurfaces: React.FC = () => (
  <section className="section">
    <Title level={2} style={{ textAlign: 'center', marginBottom: 48 }}>
      Three Access Surfaces, One Engine
    </Title>
    <Row gutter={[24, 24]}>
      {surfaces.map((s) => (
        <Col xs={24} md={8} key={s.title}>
          <Card
            hoverable
            style={{ height: '100%', borderTop: `3px solid ${s.color}` }}
          >
            <div style={{ marginBottom: 16 }}>{s.icon}</div>
            <Title level={4} style={{ marginBottom: 8 }}>{s.title}</Title>
            <Paragraph type="secondary">{s.desc}</Paragraph>
            <div>
              {s.tags.map((t) => (
                <Tag key={t} color={s.color}>{t}</Tag>
              ))}
            </div>
          </Card>
        </Col>
      ))}
    </Row>

    <Title level={3} style={{ marginTop: 64, marginBottom: 24 }}>
      Core Capabilities
    </Title>
    <Row gutter={[16, 16]}>
      {capabilities.map((c) => (
        <Col xs={24} sm={12} key={c.label}>
          <Card size="small" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 20, color: '#059669' }}>{c.icon}</span>
            <div>
              <Text strong>{c.label}</Text>
              <br />
              <Text type="secondary" style={{ fontSize: '0.85rem' }}>{c.desc}</Text>
            </div>
          </Card>
        </Col>
      ))}
    </Row>
  </section>
);

export default AccessSurfaces;
