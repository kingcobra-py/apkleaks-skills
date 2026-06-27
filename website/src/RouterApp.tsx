import React from 'react';
import { Routes, Route } from 'react-router-dom';
import App from './App';
import Hero from './components/Hero';
import HomePage from './components/HomePage';
import FeaturesPage from './components/FeaturesPage';
import SkillsPage from './components/SkillsPage';
import InstallPage from './components/InstallPage';

const RouterApp: React.FC = () => (
  <Routes>
    <Route element={<App />}>
      <Route path="/" element={<><Hero /><HomePage /></>} />
      <Route path="/features" element={<FeaturesPage />} />
      <Route path="/skills" element={<SkillsPage />} />
      <Route path="/install" element={<InstallPage />} />
    </Route>
  </Routes>
);

export default RouterApp;
