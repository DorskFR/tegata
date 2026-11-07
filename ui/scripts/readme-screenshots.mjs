#!/usr/bin/env node
/**
 * Seeds a throwaway tegata with fake devices and captures the README screenshots.
 *
 * Start an empty in-memory instance first (see "Development" in the README), then
 *   npm run readme:shots [-- --url http://localhost:5440 --authz http://localhost:5441]
 */
import { mkdir } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { chromium } from 'playwright';

const { values } = parseArgs({
	options: {
		url: { type: 'string', default: 'http://localhost:5440' },
		authz: { type: 'string', default: 'http://localhost:5441' },
		token: { type: 'string', default: 'readme-demo-token' },
		out: { type: 'string', default: '../docs/assets' }
	}
});

const VIEWPORT = { width: 1280, height: 900 };
const THEMES = ['light', 'dark'];

const DEVICES = [
	{ name: 'Work laptop', owner: 'alice', groups: ['admin'], days: 365, seen: '203.0.113.24' },
	{ name: 'iPhone 16', owner: 'alice', groups: ['family'], days: 365, seen: '198.51.100.7' },
	{ name: 'Living room tablet', owner: 'family', groups: ['family', 'media'], days: 90 },
	{ name: 'Pixel 9', owner: 'bob', groups: ['family'], days: 10, seen: '198.51.100.31' },
	{ name: 'Old desktop', owner: 'bob', groups: [], days: 365, revoke: true },
	{ name: 'Guest phone', owner: 'carol', groups: ['guests'], days: 30, pending: true }
];

const UA = {
	'Work laptop': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 15_2)',
	'iPhone 16': 'Mozilla/5.0 (iPhone; CPU iPhone OS 19_1 like Mac OS X)',
	'Pixel 9': 'Mozilla/5.0 (Linux; Android 16; Pixel 9)'
};

async function api(page, method, path, body) {
	return page.evaluate(
		async ({ method, path, body }) => {
			const res = await fetch(path, {
				method,
				headers: body ? { 'content-type': 'application/json' } : {},
				body: body ? JSON.stringify(body) : undefined
			});
			if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${await res.text()}`);
			return res.status === 204 ? null : res.json();
		},
		{ method, path, body }
	);
}

async function install(enrollment) {
	const res = await fetch(`${enrollment.url}/device.p12`);
	if (!res.ok) throw new Error(`download ${enrollment.url}: ${res.status}`);
	await res.arrayBuffer();
}

async function touch(device, ip) {
	await fetch(`${values.authz}/authz`, {
		headers: {
			'x-forwarded-client-cert': `Hash=${device.cert.fingerprint_sha256}`,
			'x-forwarded-for': ip,
			'x-forwarded-host': 'photos.example.com',
			'user-agent': UA[device.name] ?? 'Mozilla/5.0'
		}
	});
}

async function seed(page) {
	const cdp = await page.context().newCDPSession(page);
	await cdp.send('WebAuthn.enable');
	await cdp.send('WebAuthn.addVirtualAuthenticator', {
		options: {
			protocol: 'ctap2',
			transport: 'internal',
			hasResidentKey: true,
			hasUserVerification: true,
			isUserVerified: true,
			automaticPresenceSimulation: true
		}
	});
	await page.goto(`${values.url}/setup`, { waitUntil: 'networkidle' });
	await page.getByLabel('Setup token').fill(values.token);
	await page.getByLabel('Passkey name').fill('Laptop');
	await page.getByRole('button', { name: 'Register passkey' }).click();
	await page.getByRole('heading', { name: 'Devices' }).waitFor();

	for (const d of DEVICES) {
		const created = await api(page, 'POST', '/api/devices', {
			name: d.name,
			owner: d.owner,
			groups: d.groups,
			validity_days: d.days
		});
		if (d.pending) continue;
		await install(created.enrollment);
		const device = (await api(page, 'GET', '/api/devices')).find((x) => x.name === d.name);
		if (d.seen) await touch(device, d.seen);
		if (d.revoke) await api(page, 'POST', `/api/devices/${device.id}/revoke`);
	}
	const tablet = (await api(page, 'GET', '/api/devices')).find(
		(x) => x.name === 'Living room tablet'
	);
	await api(page, 'POST', `/api/devices/${tablet.id}/rotate`, { validity_days: 365 });
	// last seen is written by the once-a-minute sweep
	for (let i = 0; i < 70; i++) {
		const devices = await api(page, 'GET', '/api/devices');
		if (devices.filter((x) => x.last_seen).length === 3) return;
		await page.waitForTimeout(1000);
	}
	throw new Error('last seen never showed up');
}

async function shoot(page, file, clip) {
	for (const theme of THEMES) {
		await page.emulateMedia({ colorScheme: theme });
		await page.waitForTimeout(300);
		const box = clip ? await clip() : undefined;
		const path = `${values.out}/${file}-${theme}.png`;
		await page.screenshot({ path, clip: box });
		console.log(path);
	}
}

await mkdir(values.out, { recursive: true });
const browser = await chromium.launch();
try {
	const page = await browser.newPage({
		viewport: VIEWPORT,
		deviceScaleFactor: 2,
		reducedMotion: 'reduce'
	});
	await seed(page);

	await page.reload({ waitUntil: 'networkidle' });
	await page.evaluate(() => document.fonts.ready);
	await page.mouse.move(0, 0);
	const listClip = async () => {
		const bottom = await page.evaluate(() =>
			Math.ceil(document.querySelector('ul.devices').getBoundingClientRect().bottom)
		);
		return { x: 0, y: 0, width: VIEWPORT.width, height: bottom + 32 };
	};
	await shoot(page, 'devices', listClip);

	await page.getByRole('button', { name: 'New device' }).first().click();
	await page.getByLabel('Device name').fill('Kitchen display');
	await page.getByLabel('Owner').fill('family');
	await page
		.getByRole('dialog')
		.getByRole('button', { name: /create/i })
		.click();
	const panel = page.locator('section.panel');
	await panel.waitFor();
	await page.waitForTimeout(500);
	await page.mouse.move(0, 0);
	await shoot(page, 'enroll', async () => {
		const b = await panel.boundingBox();
		return { x: b.x - 8, y: b.y - 8, width: b.width + 16, height: b.height + 16 };
	});
} finally {
	await browser.close();
}
