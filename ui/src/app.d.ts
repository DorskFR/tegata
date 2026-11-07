declare global {
	namespace App {
		interface PageData {
			session?: import('#lib/api').Session;
		}
	}
}

export {};
