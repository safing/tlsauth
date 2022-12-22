all: success-tests fail-tests

success-tests:
	curl --fail-with-body -ki --cert certs/alice-client.pem --key certs/alice-client-key.pem https://127.0.0.1
	curl --fail-with-body -ki --cert certs/alice1-client.pem --key certs/alice1-client-key.pem https://127.0.0.1
	curl --fail-with-body -ki --cert certs/bob1-client.pem --key certs/bob1-client-key.pem https://127.0.0.1
	curl --fail-with-body -ki --cert certs/charlie@example.org-client.pem --key certs/charlie@example.org-client-key.pem https://127.0.0.1

fail-tests:
	curl --fail-with-body -ki http://127.0.0.1 || exit 0 && exit 1
	curl --fail-with-body -ki https://127.0.0.1 || exit 0 && exit 1
	curl --fail-with-body -ki --cert certs/bob-client.pem --key certs/bob-client-key.pem https://127.0.0.1 || exit 0 && exit 1
	curl --fail-with-body -ki --cert certs/mallory-client.pem --key certs/mallory-client-key.pem https://127.0.0.1 || exit 0 && exit 1

.PHONY: all
