import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  root: 'app',
  base: '/workspace/',
  plugins: [react()],
  // The 3D engine chunk loads only on the Hardware tab; the main bundle stays under the default limit.
  build: { chunkSizeWarningLimit: 650, outDir: '../dist', emptyOutDir: true, rollupOptions: { output: { manualChunks: { graph: ['@xyflow/react'], validation: ['zod'] } } } },
  server: {
    strictPort: true,
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/preauth': 'http://127.0.0.1:8000',
      '/meta': 'http://127.0.0.1:8000',
      '/readyz': 'http://127.0.0.1:8000',
    },
  },
});