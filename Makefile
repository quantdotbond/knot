# CCTS research prototype build.
# Header-only library under include/; three executables.
CXX      ?= g++
CXXFLAGS ?= -std=c++20 -O2 -Wall -Wextra -Iinclude

.PHONY: all test bench vectors analyze clean ci ci-nightly ci-release production-tests

all: tests/run_tests tests/gen_vectors bench/run_bench

tests/run_tests: tests/test_main.cpp $(wildcard include/ccts/*.hpp)
	$(CXX) $(CXXFLAGS) tests/test_main.cpp -o $@

tests/gen_vectors: tests/gen_vectors.cpp $(wildcard include/ccts/*.hpp)
	$(CXX) $(CXXFLAGS) tests/gen_vectors.cpp -o $@

tests/export_instance: tests/export_instance.cpp $(wildcard include/ccts/*.hpp)
	$(CXX) $(CXXFLAGS) tests/export_instance.cpp -o $@

bench/run_bench: bench/bench_main.cpp $(wildcard include/ccts/*.hpp)
	$(CXX) $(CXXFLAGS) bench/bench_main.cpp -o $@

# Run the full validation suite.
test: tests/run_tests
	./tests/run_tests

# Regenerate deterministic example vectors.
vectors: tests/gen_vectors
	@mkdir -p vectors
	./tests/gen_vectors

# Run benchmarks (writes results/*.csv).
bench: bench/run_bench
	@mkdir -p results
	./bench/run_bench

# Statistics + plots (requires python3 with numpy, pandas, matplotlib).
analyze:
	python3 analysis/analyze.py

clean:
	rm -f tests/run_tests tests/gen_vectors tests/export_instance bench/run_bench
	rm -rf build ci-artifacts

# ---------------------------------------------------------------------------
# Production-assurance layer (production/, scripts/): the canonical way to
# reproduce every CI check from a clean checkout (scripts/ci.sh).
#   make ci            fast blocking checks (what a pull request runs)
#   make ci-nightly    + extended fuzzing, valgrind, timing, benchmark regression
#   make ci-release    + release artifact assembly (nothing is published)
#   make production-tests   just build and run the production test suite
# ---------------------------------------------------------------------------
ci:
	scripts/ci.sh quick
ci-nightly:
	scripts/ci.sh nightly
ci-release:
	scripts/ci.sh release
production-tests:
	$(MAKE) -C production run-tests
