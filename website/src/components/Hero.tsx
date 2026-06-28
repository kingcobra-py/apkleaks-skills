import React from 'react';
import { Typography, Button, Space } from 'antd';
import { RocketOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';

const { Title, Paragraph } = Typography;

const Hero: React.FC = () => {
  const { t } = useTranslation();

  return (
    <section className="hero-bg" style={{ color: '#fff', textAlign: 'center', padding: '120px 24px 80px' }}>
      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.7 }}
      >
        <Title level={1} style={{ color: '#fff', fontSize: '3.5rem', marginBottom: 12, fontWeight: 800 }}>
          <span className="gradient-text">{t('hero.title')}</span>
        </Title>
        <Paragraph
          style={{
            color: '#94a3b8',
            fontSize: '1.25rem',
            maxWidth: 660,
            margin: '0 auto 40px',
            lineHeight: 1.8,
          }}
        >
          {t('hero.subtitle')}
        </Paragraph>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, delay: 0.4 }}
      >
        <Space size="middle" wrap>
          <Link to="/install">
            <Button
              type="primary"
              size="large"
              icon={<RocketOutlined />}
              style={{
                height: 48,
                paddingInline: 32,
                borderRadius: 10,
                fontWeight: 600,
                background: 'linear-gradient(135deg, #4f46e5, #7c3aed)',
                border: 'none',
                boxShadow: '0 4px 14px rgba(79,70,229,.35)',
              }}
            >
              {t('hero.installBtn')}
            </Button>
          </Link>
          <Link to="/features">
            <Button
              size="large"
              ghost
              icon={<PlayCircleOutlined />}
              style={{
                height: 48,
                paddingInline: 28,
                borderRadius: 10,
                color: '#e2e8f0',
                borderColor: '#475569',
              }}
            >
              {t('hero.exploreBtn')}
            </Button>
          </Link>
        </Space>
      </motion.div>

      {/* decorative orbs */}
      <div style={{ position: 'absolute', top: '15%', left: '10%', width: 260, height: 260, borderRadius: '50%', background: 'radial-gradient(circle, rgba(79,70,229,.12), transparent 70%)', pointerEvents: 'none' }} />
      <div style={{ position: 'absolute', bottom: '10%', right: '8%', width: 200, height: 200, borderRadius: '50%', background: 'radial-gradient(circle, rgba(6,182,212,.1), transparent 70%)', pointerEvents: 'none' }} />
    </section>
  );
};

export default Hero;
