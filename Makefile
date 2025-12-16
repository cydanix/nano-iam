.PHONY: testsdb test clean

testsdb:
	docker rm -f iam-postgres
	docker run --name iam-postgres -e POSTGRES_PASSWORD=mysecretpassword -p 127.0.0.1:5432:5432 -d postgres
	sleep 3

tests: testsdb
	export TEST_DATABASE_URL=postgresql://postgres:mysecretpassword@127.0.0.1:5432/postgres
	RUST_LOG=error cargo test -- --test-threads=1 --nocapture

clean:
	cargo clean
	docker rm -f iam-postgres || true