import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';
import terser from '@rollup/plugin-terser';

export default defineConfig({
	plugins: [
		sveltekit(),
		terser()],
});
