import React from 'react';
import { Typography, Row, Col, Card, Tag, Divider } from 'antd';
import {
  BugOutlined,
  CodeOutlined,
  ExperimentOutlined,
  DesktopOutlined,
  MobileOutlined,
  BuildOutlined,
  FunctionOutlined,
  AppstoreOutlined,
  MonitorOutlined,
} from '@ant-design/icons';

const { Title, Paragraph, Text } = Typography;

const skills = [
  {
    name: 'rev-apkleaks',
    trigger: '/rev-apkleaks',
    icon: <BugOutlined />,
    desc: 'Scan APK for secrets, endpoints & credentials via CLI + MCP.',
    color: '#2563eb',
  },
  {
    name: 'rev-dex-dumper',
    trigger: '/rev-dex-dumper',
    icon: <CodeOutlined />,
    desc: 'DEX disassembly — class definitions, method signatures, bytecode.',
    color: '#7c3aed',
  },
  {
    name: 'rev-frida',
    trigger: '/rev-frida',
    icon: <ExperimentOutlined />,
    desc: 'Dynamic instrumentation: hook, trace, bypass SSL pinning / root detection.',
    color: '#059669',
  },
  {
    name: 'rev-idapython',
    trigger: '/rev-idapython',
    icon: <DesktopOutlined />,
    desc: 'IDA Pro Python scripting for automated binary analysis.',
    color: '#d97706',
  },
  {
    name: 'rev-ios-dump',
    trigger: '/rev-ios-dump',
    icon: <MobileOutlined />,
    desc: 'Dump / decrypt iOS apps (IPA) from jailbroken devices.',
    color: '#dc2626',
  },
  {
    name: 'rev-struct',
    trigger: '/rev-struct',
    icon: <BuildOutlined />,
    desc: 'Reconstruct struct/class layout & field offsets from memory access patterns.',
    color: '#0891b2',
  },
  {
    name: 'rev-symbol',
    trigger: '/rev-symbol',
    icon: <FunctionOutlined />,
    desc: 'Symbol table extraction, imports/exports & library function analysis.',
    color: '#2563eb',
  },
  {
    name: 'rev-u3d-dump',
    trigger: '/rev-u3d-dump',
    icon: <AppstoreOutlined />,
    desc: 'Unity3D asset extraction — Assembly-CSharp.dll, bundles, shaders.',
    color: '#7c3aed',
  },
  {
    name: 'rev-unicorn-debug',
    trigger: '/rev-unicorn-debug',
    icon: <MonitorOutlined />,
    desc: 'CPU emulation & debugging (ARM/x86/MIPS…) with Unicorn.',
    color: '#059669',
  },
];

const SkillsPage: React.FC = () => (
  <section className="section">
    <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
      9 Reverse-Engineering Skills
    </Title>
    <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 48 }}>
      Auto-discovered on plugin install. Triggered by intent, chain seamlessly.
      Each follows progressive-disclosure: lean SKILL.md on trigger, deep reference.md on demand.
    </Paragraph>
    <Row gutter={[24, 24]}>
      {skills.map((s) => (
        <Col xs={24} sm={12} md={8} key={s.name}>
          <Card
            hoverable
            style={{ height: '100%', borderTop: `3px solid ${s.color}` }}
          >
            <div style={{ fontSize: 24, color: s.color, marginBottom: 8 }}>{s.icon}</div>
            <Title level={4} style={{ marginBottom: 4 }}>{s.name}</Title>
            <Tag color={s.color}>{s.trigger}</Tag>
            <Paragraph type="secondary" style={{ marginTop: 12 }}>{s.desc}</Paragraph>
          </Card>
        </Col>
      ))}
    </Row>

    <Divider style={{ margin: '48px 0' }} />

    <Title level={3}>Progressive-Disclosure Anatomy</Title>
    <Paragraph type="secondary">
      Every skill follows the canonical <Text code>anthropics/skills</Text> anatomy:
    </Paragraph>
    <Row gutter={[16, 16]}>
      <Col xs={24} md={8}>
        <Card size="small">
          <Text strong>SKILL.md</Text> — lean entry loaded on trigger: overview, execution flow, hard rules.
        </Card>
      </Col>
      <Col xs={24} md={8}>
        <Card size="small">
          <Text strong>references/reference.md</Text> — deep docs read on demand: full catalogs, error codes, edge cases.
        </Card>
      </Col>
      <Col xs={24} md={8}>
        <Card size="small">
          <Text strong>LICENSE.txt</Text> — Apache-2.0, mirrors root LICENSE per spec.
        </Card>
      </Col>
    </Row>
  </section>
);

export default SkillsPage;
