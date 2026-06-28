import React from 'react';
import { Typography, Card, Row, Col, Statistic, Tag, Divider } from 'antd';
import {
  BugOutlined,
  ApiOutlined,
  CodeOutlined,
  ThunderboltOutlined,
  SafetyCertificateOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
} from '@ant-design/icons';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';

const { Title, Paragraph, Text } = Typography;

const categories = [
  'Cloud', 'AI / LLM', 'Messaging', 'Payments',
  'DevOps', 'Monitoring', 'CDN', 'Hosting',
  'Identity', 'Private keys', 'Android', 'Generic',
];

const FeaturesPage: React.FC = () => {
  const { t } = useTranslation();

  const contractItems = [
    { icon: <SafetyCertificateOutlined />, title: t('features.contract.ok.title'), desc: t('features.contract.ok.desc'), color: '#4f46e5' },
    { icon: <ApiOutlined />, title: t('features.contract.schema.title'), desc: t('features.contract.schema.desc'), color: '#06b6d4' },
    { icon: <BugOutlined />, title: t('features.contract.critical.title'), desc: t('features.contract.critical.desc'), color: '#ef4444' },
  ];

  return (
    <section className="section">
      {/* Feature tree */}
      <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
        {t('features.title')}
      </Title>
      <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 32 }}>
        {t('features.subtitle')}
      </Paragraph>

      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        whileInView={{ opacity: 1, scale: 1 }}
        viewport={{ once: true }}
        transition={{ duration: 0.6 }}
      >
        <Card className="glass-card" style={{ textAlign: 'center', margin: '0 auto 48px', maxWidth: 920 }}>
          <img
            src="https://raw.githubusercontent.com/android-security-engineer/apkleaks-skills/master/docs/feature-tree.svg"
            alt="APKLeaks for AI Agents — feature tree"
            style={{ maxWidth: '100%', height: 'auto' }}
          />
        </Card>
      </motion.div>

      <Divider />

      {/* Detection stats */}
      <Title level={3}>{t('features.detection.title')}</Title>
      <Row gutter={[24, 24]} style={{ marginBottom: 32 }}>
        <Col xs={12} sm={6}>
          <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }}>
            <Statistic title={t('features.detection.patterns')} value={95} prefix={<BugOutlined />} suffix="+" />
          </motion.div>
        </Col>
        <Col xs={12} sm={6}>
          <Statistic title={t('features.detection.categories')} value={12} prefix={<CodeOutlined />} />
        </Col>
        <Col xs={12} sm={6}>
          <Statistic title={t('features.detection.mcpTools')} value={12} prefix={<ApiOutlined />} />
        </Col>
        <Col xs={12} sm={6}>
          <Statistic title={t('features.detection.cliSubs')} value={13} prefix={<ThunderboltOutlined />} />
        </Col>
      </Row>
      <div className="badge-strip" style={{ marginBottom: 8 }}>
        {categories.map((c) => (
          <Tag key={c} color="blue" style={{ borderRadius: 6 }}>{c}</Tag>
        ))}
      </div>

      <Divider />

      {/* Agent contract */}
      <Title level={3}>{t('features.contract.title')}</Title>
      <Paragraph type="secondary" style={{ marginBottom: 24, maxWidth: 600 }}>
        {t('features.contract.subtitle')}
      </Paragraph>
      <Row gutter={[24, 24]}>
        {contractItems.map((c, i) => (
          <Col xs={24} md={8} key={c.title}>
            <motion.div custom={i} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: i * 0.15, duration: 0.4 }}>
              <Card hoverable className="glass-card" style={{ height: '100%', borderTop: `3px solid ${c.color}` }}>
                <div style={{ fontSize: 24, color: c.color, marginBottom: 12 }}>{c.icon}</div>
                <Title level={5}>{c.title}</Title>
                <Paragraph type="secondary">{c.desc}</Paragraph>
              </Card>
            </motion.div>
          </Col>
        ))}
      </Row>

      <Divider />

      {/* Response envelope */}
      <Title level={4}>{t('features.envelope.title')}</Title>
      <Paragraph type="secondary">{t('features.envelope.subtitle')}</Paragraph>
      <Row gutter={[24, 24]}>
        <Col xs={24} md={12}>
          <Card style={{ background: '#f0fdf4', borderColor: '#86efac', borderRadius: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <CheckCircleOutlined style={{ color: '#166534', fontSize: 18 }} />
              <Text strong style={{ color: '#166534' }}>{t('features.envelope.success')}</Text>
            </div>
            <pre style={{ background: '#0f172a', color: '#e2e8f0', padding: 14, borderRadius: 8, fontSize: '.8rem', lineHeight: 1.5 }}>
{`{
  "ok": true,
  "timestamp": "2026-06-24T14:02:03+0800",
  "duration_ms": 123,
  "data": { /* result payload */ }
}`}
            </pre>
          </Card>
        </Col>
        <Col xs={24} md={12}>
          <Card style={{ background: '#fef2f2', borderColor: '#fca5a5', borderRadius: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <CloseCircleOutlined style={{ color: '#991b1b', fontSize: 18 }} />
              <Text strong style={{ color: '#991b1b' }}>{t('features.envelope.error')}</Text>
            </div>
            <pre style={{ background: '#0f172a', color: '#e2e8f0', padding: 14, borderRadius: 8, fontSize: '.8rem', lineHeight: 1.5 }}>
{`{
  "ok": false,
  "timestamp": "2026-06-24T14:02:03+0800",
  "error": "APK file not found",
  "error_code": "FILE_NOT_FOUND"
}`}
            </pre>
          </Card>
        </Col>
      </Row>
    </section>
  );
};

export default FeaturesPage;
