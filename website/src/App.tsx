import React from 'react';
import { Layout, Typography, Button, Space } from 'antd';
import { GithubOutlined, GlobalOutlined } from '@ant-design/icons';
import { Outlet } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import Navbar from './components/Navbar';

const { Footer } = Layout;
const { Text } = Typography;

const App: React.FC = () => {
  const { t, i18n } = useTranslation();
  const toggleLang = () => {
    const next = i18n.language === 'zh' ? 'en' : 'zh';
    i18n.changeLanguage(next);
    localStorage.setItem('lang', next);
  };

  return (
    <Layout style={{ minHeight: '100vh', background: 'transparent' }}>
      <Navbar />
      <Layout.Content>
        <Outlet />
      </Layout.Content>
      <Footer style={{ background: '#0f172a', textAlign: 'center', padding: '40px 24px' }}>
        <Text style={{ color: '#94a3b8' }}>
          {t('footer.copyright').replace('year', String(new Date().getFullYear()))} — {t('footer.built')}&nbsp;
          <a href="https://github.com/dwisiswant0/apkleaks" target="_blank" rel="noreferrer">
            dwisiswant0/apkleaks
          </a>
        </Text>
        <br />
        <Space style={{ marginTop: 12 }}>
          <a href="https://github.com/android-security-engineer/apkleaks-skills" target="_blank" rel="noreferrer" style={{ color: '#818cf8' }}>
            <GithubOutlined /> GitHub
          </a>
          <Button type="text" size="small" icon={<GlobalOutlined />} onClick={toggleLang} style={{ color: '#818cf8' }}>
            {i18n.language === 'zh' ? 'EN' : '中文'}
          </Button>
        </Space>
      </Footer>
    </Layout>
  );
};

export default App;
