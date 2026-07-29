import React from 'react';
import { Navigate, Routes, Route } from 'react-router-dom';
import App from './App';
import DashboardPage from './components/DashboardPage';

const RouterApp: React.FC = () => (
  <Routes>
    <Route element={<App />}>
      <Route path="/" element={<Navigate to="/dashboard" replace />} />
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="*" element={<Navigate to="/dashboard" replace />} />
    </Route>
  </Routes>
);

export default RouterApp;
