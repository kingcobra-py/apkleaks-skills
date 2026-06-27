import React from 'react';
import { Typography, Button, Space } from 'antd';
import { RocketOutlined, PlayCircleOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';

const { Title, Paragraph } = Typography;

const Hero: React.FC = () => (
  <section
    style={{
      background: 'linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%)',
      color: '#fff',
      textAlign: 'center',
      padding: '120px 24px 80px',
    }}
  >
    <Title level={1} style={{ color: '#fff', fontSize: '3rem', marginBottom: 12 }}>
      APKLeaks for AI Agents
    </Title>
    <Paragraph
      style={{
        color: '#94a3b8',
        fontSize: '1.25rem',
        maxWidth: 640,
        margin: '0 auto 32px',
      }}
    >
      Find secrets, API keys, tokens and endpoints in Android APKs — re-architected for AI agents. Every surface speaks JSON, self-describes in one call, and grades its own findings.
    </Paragraph>
    <Space size="middle" wrap>
      <Link to="/install">
        <Button type="primary" size="large" icon={<RocketOutlined />}>
          Install Plugin
        </Button>
      </Link>
      <Link to="/features">
        <Button size="large" ghost icon={<PlayCircleOutlined />} style={{ color: '#fff', borderColor: '#475569' }}>
          Explore Features
        </Button>
      </Link>
    </Space>
  </section>
);

export default Hero;
