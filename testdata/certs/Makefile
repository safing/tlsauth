rootCA.pem:
	CAROOT=. mkcert localhost
	CAROOT=. mkcert -client alice
	CAROOT=. mkcert -client alice1
	CAROOT=. mkcert -client bob
	CAROOT=. mkcert -client bob1
	CAROOT=. mkcert -client charlie@example.org
	CAROOT=. mkcert -client mallory

reset:
	rm -f *.pem

.PHONY: reset
