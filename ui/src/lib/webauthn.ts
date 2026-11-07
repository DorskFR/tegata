import { api } from './api';

export function passkeysSupported(): boolean {
	return (
		typeof PublicKeyCredential !== 'undefined' &&
		typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function' &&
		typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function'
	);
}

export class WebAuthnError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'WebAuthnError';
	}
}

function describe(e: unknown): WebAuthnError {
	if (e instanceof DOMException) {
		if (e.name === 'NotAllowedError') {
			return new WebAuthnError('The passkey prompt was cancelled or timed out.');
		}
		if (e.name === 'InvalidStateError') {
			return new WebAuthnError('This authenticator is already registered.');
		}
		if (e.name === 'SecurityError') {
			return new WebAuthnError('Passkeys need a secure (HTTPS) origin that matches the server.');
		}
	}
	return new WebAuthnError(e instanceof Error ? e.message : 'Passkey operation failed.');
}

export async function loginWithPasskey(): Promise<void> {
	if (!passkeysSupported()) throw new WebAuthnError('This browser does not support passkeys.');
	const { publicKey } = await api.auth.loginStart();
	let credential: Credential | null;
	try {
		credential = await navigator.credentials.get({
			publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey)
		});
	} catch (e) {
		throw describe(e);
	}
	if (!(credential instanceof PublicKeyCredential)) {
		throw new WebAuthnError('No passkey was returned.');
	}
	await api.auth.loginFinish(credential.toJSON());
}

export async function registerPasskey(name: string, setupToken?: string): Promise<void> {
	if (!passkeysSupported()) throw new WebAuthnError('This browser does not support passkeys.');
	const { publicKey } = await api.auth.registerStart(name, setupToken);
	let credential: Credential | null;
	try {
		credential = await navigator.credentials.create({
			publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey)
		});
	} catch (e) {
		throw describe(e);
	}
	if (!(credential instanceof PublicKeyCredential)) {
		throw new WebAuthnError('No passkey was created.');
	}
	await api.auth.registerFinish(credential.toJSON());
}
