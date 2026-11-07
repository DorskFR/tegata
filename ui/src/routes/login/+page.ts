import { redirect } from '@sveltejs/kit';
import { api } from '#lib/api';
import type { PageLoad } from './$types';

export const load: PageLoad = async () => {
	const session = await api.session();
	if (session.setup_required) redirect(307, '/setup');
	if (session.authenticated) redirect(307, '/');
	return { session };
};
