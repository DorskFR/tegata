import { redirect } from '@sveltejs/kit';
import { api } from '#lib/api';
import type { PageLoad } from './$types';

export const load: PageLoad = async () => {
	const session = await api.session();
	if (!session.setup_required) redirect(307, session.authenticated ? '/' : '/login');
	return { session };
};
