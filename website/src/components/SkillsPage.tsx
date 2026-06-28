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
import { useTranslation } from 'react-i18next';
import { motion } from 'framer-motion';

const { Title, Paragraph, Text } = Typography;

const skills = [
  { name: 'rev-apkleaks', trigger: '/rev-apkleaks', icon: <BugOutlined />, color: '#4f46e5' },
  { name: 'rev-dex-dumper', trigger: '/rev-dex-dumper', icon: <CodeOutlined />, color: '#7c3aed' },
  { name: 'rev-frida', trigger: '/rev-frida', icon: <ExperimentOutlined />, color: '#10b981' },
  { name: 'rev-idapython', trigger: '/rev-idapython', icon: <DesktopOutlined />, color: '#f59e0b' },
  { name: 'rev-ios-dump', trigger: '/rev-ios-dump', icon: <MobileOutlined />, color: '#ef4444' },
  { name: 'rev-struct', trigger: '/rev-struct', icon: <BuildOutlined />, color: '#06b6d4' },
  { name: 'rev-symbol', trigger: '/rev-symbol', icon: <FunctionOutlined />, color: '#4f46e5' },
  { name: 'rev-u3d-dump', trigger: '/rev-u3d-dump', icon: <AppstoreOutlined />, color: '#7c3aed' },
  { name: 'rev-unicorn-debug', trigger: '/rev-unicorn-debug', icon: <MonitorOutlined />, color: '#10b981' },
];

const SkillsPage: React.FC = () => {
  const { t } = useTranslation();

  return (
    <section className="section">
      <Title level={2} style={{ textAlign: 'center', marginBottom: 8 }}>
        {t('skills.title')}
      </Title>
      <Paragraph style={{ textAlign: 'center', color: '#64748b', marginBottom: 48, maxWidth: 640, margin: '0 auto 48px' }}>
        {t('skills.subtitle')}
      </Paragraph>

      <Row gutter={[24, 24]}>
        {skills.map((s, i) => (
          <Col xs={24} sm={12} md={8} key={s.name}>
            <motion.div
              initial={{ opacity: 0, y: 24 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: i * 0.08, duration: 0.4 }}
            >
              <Card
                hoverable
                className="glass-card"
                style={{ height: '100%', borderTop: `3px solid ${s.color}` }}
              >
                <div style={{ fontSize: 28, color: s.color, marginBottom: 8 }}>{s.icon}</div>
                <Title level={4} style={{ marginBottom: 4, fontSize: '1.05rem' }}>{s.name}</Title>
                <Tag color={s.color} style={{ borderRadius: 6 }}>{s.trigger}</Tag>
              </Card>
            </motion.div>
          </Col>
        ))}
      </Row>

      <Divider style={{ margin: '56px 0' }} />

      <Title level={3}>{t('skills.anatomy.title')}</Title>
      <Paragraph type="secondary">{t('skills.anatomy.subtitle')}</Paragraph>
      <Row gutter={[24, 24]}>
        <Col xs={24} md={8}>
          <motion.div initial={{ opacity: 0, x: -20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}>
            <Card className="glass-card" style={{ borderTop: '3px solid #4f46e5' }}>
              <Text strong style={{ color: '#4f46e5' }}>SKILL.md</Text>
              <Paragraph type="secondary" style={{ marginTop: 8 }}>{t('skills.anatomy.skill')}</Paragraph>
            </Card>
          </motion.div>
        </Col>
        <Col xs={24} md={8}>
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }}>
            <Card className="glass-card" style={{ borderTop: '3px solid #06b6d4' }}>
              <Text strong style={{ color: '#06b6d4' }}>references/reference.md</Text>
              <Paragraph type="secondary" style={{ marginTop: 8 }}>{t('skills.anatomy.ref')}</Paragraph>
            </Card>
          </motion.div>
        </Col>
        <Col xs={24} md={8}>
          <motion.div initial={{ opacity: 0, x: 20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}>
            <Card className="glass-card" style={{ borderTop: '3px solid #10b981' }}>
              <Text strong style={{ color: '#10b981' }}>LICENSE.txt</Text>
              <Paragraph type="secondary" style={{ marginTop: 8 }}>{t('skills.anatomy.license')}</Paragraph>
            </Card>
          </motion.div>
        </Col>
      </Row>
    </section>
  );
};

export default SkillsPage;
