import React from 'react';
import { Layout, Menu, Button, Space } from 'antd';
import { GithubOutlined, GlobalOutlined } from '@ant-design/icons';
import { Link, useLocation } from 'react-router-dom';
import { useTranslation } from 'react-i18next';

const { Header } = Layout;

const Navbar: React.FC = () => {
  const { t, i18n } = useTranslation();
  const location = useLocation();
  const selectedKey = location.pathname;

  const toggleLang = () => {
    const next = i18n.language === 'zh' ? 'en' : 'zh';
    i18n.changeLanguage(next);
    localStorage.setItem('lang', next);
  };

  const items = [
    { key: '/', label: <Link to="/">{t('nav.home')}</Link> },
    { key: '/features', label: <Link to="/features">{t('nav.features')}</Link> },
    { key: '/skills', label: <Link to="/skills">{t('nav.skills')}</Link> },
    { key: '/install', label: <Link to="/install">{t('nav.install')}</Link> },
    { key: '/dashboard', label: <Link to="/dashboard">{t('nav.dashboard')}</Link> },
  ];

  return (
    <Header
      style={{
        background: '#0f172a',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 32px',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        borderBottom: '1px solid #1e293b',
      }}
    >
      <Link to="/" style={{ textDecoration: 'none' }}>
        <span style={{ color: '#fff', fontSize: '1.2rem', fontWeight: 700 }}>APKLeaks</span>
        <span style={{ color: '#818cf8', fontWeight: 400, marginLeft: 6 }}>for AI Agents</span>
      </Link>
      <Menu
        theme="dark"
        mode="horizontal"
        selectedKeys={[selectedKey]}
        items={items}
        style={{ background: 'transparent', borderBottom: 'none', flex: 1, justifyContent: 'center' }}
      />
      <Space>
        <Button
          type="text"
          size="small"
          icon={<GlobalOutlined />}
          onClick={toggleLang}
          style={{ color: '#818cf8', fontSize: '0.9rem' }}
        >
          {i18n.language === 'zh' ? 'EN' : '中文'}
        </Button>
        <a href="https://github.com/android-security-engineer/apkleaks-skills" target="_blank" rel="noreferrer" style={{ color: '#94a3b8', fontSize: '1.2rem' }}>
          <GithubOutlined />
        </a>
      </Space>
    </Header>
  );
};

export default Navbar;
