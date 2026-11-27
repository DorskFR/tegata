import { createPasskey, getPasskey, passkeyError, passkeysSupported } from '@dorsk/kagi';
import { ApiError, api } from './api';

export { passkeysSupported };

async function ceremony<T>(run: () => Promise<T>, fallback: string): Promise<T> {
	if (!passkeysSupported()) throw new Error('This browser does not support passkeys.');
	try {
		return await run();
	} catch (e) {
		if (e instanceof ApiError) throw e;
		throw new Error(passkeyError(e, fallback), { cause: e });
	}
}

export function loginWithPasskey(): Promise<void> {
	return ceremony(async () => {
		const credential = await getPasskey(await api.auth.loginStart());
		if (!credential) throw new Error('No passkey was chosen.');
		await api.auth.loginFinish(credential);
	}, 'Sign-in failed.');
}

export function registerPasskey(name: string, setupToken?: string): Promise<void> {
	return ceremony(async () => {
		const credential = await createPasskey(await api.auth.registerStart(name, setupToken));
		await api.auth.registerFinish(credential);
	}, 'Adding the passkey failed.');
}
