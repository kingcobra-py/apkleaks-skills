import React from 'react';
import ReactDOM from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';
import { ConfigProvider, theme } from 'antd';
import './i18n';
import RouterApp from './RouterApp';
import './index.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ConfigProvider
      theme={{
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#22d3ee',
          colorInfo: '#38bdf8',
          colorSuccess: '#34d399',
          colorWarning: '#fbbf24',
          colorError: '#f87171',
          colorBgBase: '#0b1220',
          colorBgContainer: '#111827',
          colorBgElevated: '#0f172a',
          colorBorder: '#1e293b',
          colorText: '#e2e8f0',
          colorTextSecondary: '#94a3b8',
          borderRadius: 10,
          fontFamily:
            '"IBM Plex Sans", "Segoe UI", "Helvetica Neue", Arial, sans-serif',
        },
        components: {
          Card: {
            colorBgContainer: 'rgba(17, 24, 39, 0.92)',
          },
          Layout: {
            headerBg: '#0b1220',
            bodyBg: 'transparent',
            footerBg: '#0b1220',
          },
          Table: {
            colorBgContainer: 'transparent',
          },
        },
      }}
    >
      <BrowserRouter basename="/apkleaks-skills">
        <RouterApp />
      </BrowserRouter>
    </ConfigProvider>
  </React.StrictMode>,
);
