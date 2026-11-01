import { defineConfig } from 'vite';

// Relative base so the same build works inside Tauri and from a sub-path (GitHub Pages).
export default defineConfig({
  base: './',
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: 'es2020',
  },
});
