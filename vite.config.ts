import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import esbuild from 'esbuild';
import fs from 'fs';
import path from 'path';
import {defineConfig, type Plugin} from 'vite';

function novoraDirectIndexPlugin(): Plugin {
  return {
    name: 'novora-direct-index',
    apply: 'build',
    closeBundle() {
      const distDir = path.resolve('dist');
      const distIndexPath = path.join(distDir, 'index.html');
      if (!fs.existsSync(distIndexPath)) return;

      let html = fs.readFileSync(distIndexPath, 'utf-8');

      // Find Vite module entry script (supports ./assets/... or /assets/...)
      const scriptMatch = html.match(
        /<script\b[^>]*\btype=["']module["'][^>]*\bsrc=["']([^"']+\.js)["'][^>]*>\s*<\/script>/i
      );

      if (scriptMatch && scriptMatch[1]) {
        const rawSrc = scriptMatch[1];
        const normalizedRel = rawSrc.replace(/^\.?\//, '');
        const entryFsPath = path.join(distDir, normalizedRel);

        if (fs.existsSync(entryFsPath)) {
          // Bundle Vite output into a single classic browser IIFE script so index.html runs directly on file:// and HTTP without ES-module CORS blocks
          const result = esbuild.buildSync({
            entryPoints: [entryFsPath],
            bundle: true,
            format: 'iife',
            platform: 'browser',
            target: ['es2020'],
            minify: true,
            write: false,
            define: {
              'import.meta.url': 'window.location.href',
            },
          });

          const outCode = result.outputFiles?.[0]?.text;
          if (outCode) {
            fs.writeFileSync(entryFsPath, outCode, 'utf-8');
          }
        }

        // Convert module script tag to classic deferred script without crossorigin
        const cleanSrc = rawSrc.startsWith('./')
          ? rawSrc
          : `./${rawSrc.replace(/^\/+/, '')}`;
        html = html.replace(
          scriptMatch[0],
          `<script defer src="${cleanSrc}"></script>`
        );
      }

      // Remove modulepreload hints and crossorigin attribute on stylesheets for direct file:// compatibility
      html = html
        .replace(/<link\b[^>]*\brel=["']modulepreload["'][^>]*>\s*/gi, '')
        .replace(
          /(<link\b[^>]*\brel=["']stylesheet["'][^>]*)\s+crossorigin(?:=["'][^"']*["'])?/gi,
          '$1'
        );

      // Remove the dev-only static shell script/markup inside dist/index.html so React mounts cleanly without flicker
      html = html
        .replace(/<!--\s*STATIC_FALLBACK_START\s*-->[\s\S]*?<!--\s*STATIC_FALLBACK_END\s*-->/i, '')
        .replace(/<!--\s*FILE_DIRECT_REDIRECT_START\s*-->[\s\S]*?<!--\s*FILE_DIRECT_REDIRECT_END\s*-->/i, '');

      fs.writeFileSync(distIndexPath, html, 'utf-8');
      fs.writeFileSync(
        path.join(distDir, 'novora-ready.js'),
        'window.__NOVORA_DIST_READY__=true;\n',
        'utf-8'
      );
    },
  };
}

export default defineConfig(() => {
  return {
    base: './',
    plugins: [react(), tailwindcss(), novoraDirectIndexPlugin()],
    resolve: {
      alias: {
        '@': path.resolve('.'),
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: false,
    },
    server: {
      host: '0.0.0.0',
      allowedHosts: true as const,
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
