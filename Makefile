.PHONY: test smoke build package release clean

test:
	GOCACHE=/tmp/go-build-cache go test ./cmd/privileged-helper

smoke:
	bash scripts/compat-smoke.sh

build:
	GOCACHE=/tmp/go-build-cache bash scripts/build-helper.sh ./build/com.clashfox.helper

package:
	bash scripts/release-package.sh

release: test smoke package
	@echo "release artifacts:"
	@find release -maxdepth 3 -type f | sort

clean:
	rm -rf build release
