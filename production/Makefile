# KNOT production-assurance layer build.
# The core (include/ccts/) is consumed read-only. Everything built here lives
# under build/ (git-ignored). Invoke from the repository root: make -C production <target>
# or through scripts/ci.sh, which sets the variants (compiler, sanitizers, flags).
ROOT     := $(abspath ..)
CXX      ?= g++
BUILD    ?= $(ROOT)/build/production
VARIANT  ?= default
OUT      := $(BUILD)/$(VARIANT)
STD      ?= -std=c++20
OPT      ?= -O2
WARN     ?= -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wcast-qual \
            -Wformat=2 -Wundef -Wnull-dereference -Wdouble-promotion -Wimplicit-fallthrough
WERROR   ?= -Werror
SAN      ?=
EXTRA    ?=
INC      := -I$(ROOT)/include -I$(ROOT)/production/adapter -I$(ROOT)/production/rng -I$(ROOT)/production/tests
CXXFLAGS := $(STD) $(OPT) $(WARN) $(WERROR) $(SAN) $(EXTRA) $(INC)
LDFLAGS  ?=
CORE     := $(wildcard $(ROOT)/include/ccts/*.hpp)
ADAPTER  := $(wildcard $(ROOT)/production/adapter/*.hpp) $(wildcard $(ROOT)/production/rng/*.hpp) $(ROOT)/production/tests/test_util.hpp

TESTS    := smoke kat roundtrip negative parity portability
TEST_BINS := $(addprefix $(OUT)/,$(addsuffix _test,$(TESTS)))
TOOLS    := gen_kat gen_fuzz_seeds
TOOL_BINS := $(addprefix $(OUT)/,$(TOOLS))
FUZZERS  := $(notdir $(basename $(wildcard $(ROOT)/production/fuzz/fuzz_*.cpp)))
FUZZ_STANDALONE := $(addprefix $(OUT)/fuzz/,$(addsuffix _standalone,$(FUZZERS)))
FUZZ_LIBFUZZER  := $(addprefix $(OUT)/fuzz/,$(addsuffix _libfuzzer,$(FUZZERS)))

.PHONY: all tests tools fuzz-standalone fuzz-libfuzzer bench sidechannel run-tests clean print-fuzzers

all: tests tools
tests: $(TEST_BINS)
tools: $(TOOL_BINS)
fuzz-standalone: $(FUZZ_STANDALONE)
fuzz-libfuzzer: $(FUZZ_LIBFUZZER)
bench: $(OUT)/bench_knot
sidechannel: $(OUT)/dudect_knot $(OUT)/ctgrind_knot
print-fuzzers:
	@echo $(FUZZERS)

$(OUT) $(OUT)/fuzz:
	mkdir -p $@

$(OUT)/%_test: $(ROOT)/production/tests/%_test.cpp $(CORE) $(ADAPTER) | $(OUT)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

$(OUT)/gen_kat: $(ROOT)/production/tools/gen_kat.cpp $(CORE) $(ADAPTER) | $(OUT)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
$(OUT)/gen_fuzz_seeds: $(ROOT)/production/tools/gen_fuzz_seeds.cpp $(CORE) $(ADAPTER) | $(OUT)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Fuzz targets: one TU per target. Standalone driver (any compiler) replays
# corpora and runs a bounded mutation loop; libFuzzer build needs clang.
$(OUT)/fuzz/%_standalone: $(ROOT)/production/fuzz/%.cpp $(ROOT)/production/fuzz/standalone_driver.cpp $(CORE) $(ADAPTER) | $(OUT)/fuzz
	$(CXX) $(CXXFLAGS) -I$(ROOT)/production/fuzz $< $(ROOT)/production/fuzz/standalone_driver.cpp -o $@ $(LDFLAGS)
$(OUT)/fuzz/%_libfuzzer: $(ROOT)/production/fuzz/%.cpp $(CORE) $(ADAPTER) | $(OUT)/fuzz
	$(CXX) $(CXXFLAGS) -I$(ROOT)/production/fuzz -fsanitize=fuzzer $< -o $@ $(LDFLAGS)

$(OUT)/bench_knot: $(ROOT)/production/bench/bench_knot.cpp $(CORE) $(ADAPTER) | $(OUT)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS) -lpthread
$(OUT)/dudect_knot: $(ROOT)/production/sidechannel/dudect_knot.cpp $(CORE) $(ADAPTER) | $(OUT)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)
$(OUT)/ctgrind_knot: $(ROOT)/production/sidechannel/ctgrind_knot.cpp $(CORE) $(ADAPTER) | $(OUT)
	$(CXX) $(CXXFLAGS) $< -o $@ $(LDFLAGS)

# Run every test binary from the repository root (vectors/ paths are relative).
run-tests: $(TEST_BINS)
	@set -e; for t in $(TEST_BINS); do echo "== $$t"; (cd $(ROOT) && $$t); done

clean:
	rm -rf $(BUILD)
