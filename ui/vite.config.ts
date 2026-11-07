import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';
import type { ProxyOptions } from 'vite';
import { defineConfig } from 'vitest/config';

const backend = 'http://127.0.0.1:8080';
const enrollFile = '^/enroll/[^/]+/(profile\\.mobileconfig|device\\.p12)$';
const proxyRule: ProxyOptions = { target: backend };

export default defineConfig({
	plugins: [
		sveltekit({
			preprocess: vitePreprocess(),
			adapter: adapter({ pages: 'build', assets: 'build', fallback: 'index.html', strict: false })
		})
	],
	server: {
		proxy: {
			'/api': proxyRule,
			'/ca.crt': proxyRule,
			'/crl.pem': proxyRule,
			[enrollFile]: proxyRule
		}
	},
	test: {
		include: ['src/**/*.test.ts'],
		environment: 'node'
	}
});
