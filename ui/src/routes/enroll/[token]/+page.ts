import { ApiError, api, type EnrollInfo } from '#lib/api';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
	let info: EnrollInfo | null = null;
	let error: string | null = null;
	try {
		info = await api.enroll(params.token);
	} catch (e) {
		if (e instanceof ApiError && e.status === 404) info = null;
		else error = e instanceof Error ? e.message : 'Could not reach the server.';
	}
	return { token: params.token, info, error };
};
