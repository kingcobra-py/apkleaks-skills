import React from 'react';
import { Typography, Row, Col, Card } from 'antd';
import {
  ApiOutlined,
  CodeOutlined,
  ThunderboltOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';

const { Title, Paragraph, Text } = Typography;

const HomePage: React.FC = () => {
  const { t } = useTranslation();

  const highlights = [
    { icon: <SafetyCertificateOutlined style={{ fontSize: 36, color: '#4f46e5' }} />, title: t('home.engine.title'), desc: t('home.engine.desc'), color: '#4f46e5' },
    { icon: <ApiOutlined style={{ fontSize: 36, color: '#7c3aed' }} />, title: t('home.mcp.title'), desc: t('home.mcp.desc'), color: '#7c3aed' },
    { icon: <CodeOutlined style={{ fontSize: 36, color: '#06b6d4' }} />, title: t('home.cli.title'), desc: t('home.cli.desc'), color: '#06b6d4' },
    { icon: <ThunderboltOutlined style={{ fontSize: 36, color: '#10b981' }} />, title: t('home.skills.title'), desc: t('home.skills.desc'), color: '#10b981' },
  ];

  return (
    <>
      {/* Highlights */}
      <section className="section">
        <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
          {t('home.whyTitle')}
        </Title>
        <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 48, maxWidth: 640, margin: '0 auto 48px' }}>
          {t('home.whySubtitle')}
        </Paragraph>
        <Row gutter={[24, 24]}>
          {highlights.map((h, i) => (
            <Col xs={24} sm={12} key={h.title}>
              <motion.div
                initial={{ opacity: 0, y: 24 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.12, duration: 0.5 }}
              >
                <Card
                  hoverable
                  className="glass-card"
                  style={{ height: '100%', textAlign: 'center', borderTop: `3px solid ${h.color}` }}
                >
                  <div style={{ marginBottom: 16 }}>{h.icon}</div>
                  <Title level={4} style={{ marginBottom: 8 }}>{h.title}</Title>
                  <Paragraph type="secondary">{h.desc}</Paragraph>
                </Card>
              </motion.div>
            </Col>
          ))}
        </Row>
      </section>

      {/* Agent loop */}
      <section style={{ background: '#fff', borderTop: '1px solid #e2e8f0', borderBottom: '1px solid #e2e8f0', padding: '80px 24px' }}>
        <div style={{ maxWidth: 800, margin: '0 auto' }}>
          <Title level={3} style={{ textAlign: 'center', marginBottom: 32 }}>
            {t('home.loopTitle')}
          </Title>
          <motion.div
            initial={{ opacity: 0, scale: 0.96 }}
            whileInView={{ opacity: 1, scale: 1 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5 }}
          >
            <div className="code-block" style={{ fontSize: '.88rem' }}>
{`schema                          → learn the full API in one call
check   -f app.apk             → verify jadx + APK validity       (branch on ok)
info    -f app.apk             → package, permissions, SDK        (no decompile)
scan    -f app.apk -s high     → decompile + 95 rules, high+ only (branch on has_critical)
explain -c AWS_API_Key         → severity, impact & remediation   (per category)
search  -d <dir> -p <regex>    → grep decompiled source + context (verify a hit)`}
            </div>
          </motion.div>
          <Paragraph style={{ textAlign: 'center', color: '#64748b', marginTop: 16 }}>
            {t('home.loopNote')}
          </Paragraph>
        </div>
      </section>

      {/* CTA */}
      <section className="section" style={{ textAlign: 'center' }}>
        <Title level={3}>{t('home.ctaTitle')}</Title>
        <Paragraph type="secondary" style={{ marginBottom: 24 }}>{t('home.ctaDesc')}</Paragraph>
        <Link to="/install" style={{ textDecoration: 'none' }}>
          <Text strong style={{ fontSize: '1.1rem', color: '#4f46e5' }}>{t('home.ctaLink')}</Text>
        </Link>
      </section>
    </>
  );
};

export default HomePage;
