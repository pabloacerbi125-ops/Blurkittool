"""One-off helper to add users.last_active column.

This project mostly relies on idempotent runtime migrations in web/app.py.
If you need to apply the migration manually (e.g., before starting the app),
run:

	python -m web.migrate_add_last_active
"""

from web.app import app, ensure_users_last_active_column


def main() -> None:
		with app.app_context():
				ensure_users_last_active_column()
				print('[MIGRATION] users.last_active ensured')


if __name__ == '__main__':
		main()
