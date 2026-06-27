import React from 'react';
import { Layout, Menu } from 'antd';
import { GithubOutlined } from '@ant-design/icons';
import { Link, useLocation } from 'react-router-dom';

const { Header } = Layout;

const navItems = [
  { key: '/', label: <Link to="/">Home</Link> },
  { key: '/features', label: <Link to="/features">Features</Link> },
  { key: '/skills', label: <Link to="/skills">Skills</Link> },
  { key: '/install', label: <Link to="/install">Install</Link> },
];

const Navbar: React.FC = () => {
  const location = useLocation();
  const selectedKey = location.pathname === '/apkleaks-skills' ? '/' : location.pathname;

  return (
    <Header
      style={{
        background: '#0f172a',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '0 24px',
        position: 'sticky',
        top: 0,
        zIndex: 100,
      }}
    >
      <Link to="/" style={{ color: '#fff', fontSize: '1.2rem', fontWeight: 700, textDecoration: 'none' }}>
        APKLeaks <span style={{ color: '#60a5fa', fontWeight: 400 }}>for AI Agents</span>
      </Link>
      <Menu
        theme="dark"
        mode="horizontal"
        selectedKeys={[selectedKey]}
        items={navItems}
        style={{ background: 'transparent', borderBottom: 'none', flex: 1, justifyContent: 'center' }}
      />
      <a
        href="https://github.com/android-security-engineer/apkleaks-skills"
        target="_blank"
        rel="noreferrer"
        style={{ color: '#94a3b8', fontSize: '1.3rem' }}
      >
        <GithubOutlined />
      </a>
    </Header>
  );
};

export default Navbar;
