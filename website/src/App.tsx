import React from 'react';
import { Layout, Typography } from 'antd';
import { GithubOutlined } from '@ant-design/icons';
import { Outlet } from 'react-router-dom';
import Navbar from './components/Navbar';

const { Footer } = Layout;
const { Text } = Typography;

const App: React.FC = () => (
  <Layout style={{ minHeight: '100vh', background: '#f8fafc' }}>
    <Navbar />
    <Layout.Content>
      <Outlet />
    </Layout.Content>
    <Footer style={{ background: '#0f172a', textAlign: 'center', padding: '32px 24px' }}>
      <Text style={{ color: '#94a3b8' }}>
        © {new Date().getFullYear()} android-security-engineer — Built on&nbsp;
        <a href="https://github.com/dwisiswant0/apkleaks" target="_blank" rel="noreferrer" style={{ color: '#60a5fa' }}>
          dwisiswant0/apkleaks
        </a>
      </Text>
      <br />
      <a href="https://github.com/android-security-engineer/apkleaks-skills" target="_blank" rel="noreferrer" style={{ color: '#60a5fa' }}>
        <GithubOutlined /> GitHub
      </a>
    </Footer>
  </Layout>
);

export default App;
