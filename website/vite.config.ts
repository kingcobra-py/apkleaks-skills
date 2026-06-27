import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: '/apkleaks-skills/',  // GitHub Pages repo sub-path
});
