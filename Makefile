# === Compiler and Flags ===
CC=/opt/homebrew/opt/llvm/bin/clang
CFLAGS=-O0 -g -fPIC -fno-omit-frame-pointer
SANFLAGS=-fsanitize=address -fsanitize-address-use-after-scope -fno-optimize-sibling-calls
FUZZFLAGS=-fsanitize=fuzzer,address -fno-omit-frame-pointer -fno-optimize-sibling-calls -O0 -g

# === Targets ===
LIBSO=libcheck_password.so
DVCP_SO=libdvcp.so
PASSWD_FUZZER=passwd_fuzzer
DVCP_FUZZER=dvcp_fuzzer

.PHONY: all clean test debug

# === Default Target ===
all: $(LIBSO) $(PASSWD_FUZZER) $(DVCP_SO) $(DVCP_FUZZER)

# === Shared Library for check_password ===
$(LIBSO): check_password.c  
	$(CC) $(CFLAGS) $(SANFLAGS) -shared -o $(LIBSO) check_password.c

# === Password Fuzzer with embedded target ===
$(PASSWD_FUZZER): passwd_fuzzer.c check_password.c
	$(CC) $(FUZZFLAGS) -o $(PASSWD_FUZZER) passwd_fuzzer.c check_password.c

# === Shared Library for DVCP parser ===
$(DVCP_SO): dvcp.c
	$(CC) $(CFLAGS) -shared -o $(DVCP_SO) dvcp.c

# === DVCP Fuzzer linked against libdvcp.so ===
$(DVCP_FUZZER): dvcp_fuzzer.c $(DVCP_SO)
	$(CC) $(FUZZFLAGS) -o $(DVCP_FUZZER) dvcp_fuzzer.c -L. -ldvcp -Wl,-rpath,.

# === Debug binary for check_password ===
debug: debug_test.c check_password.c
	$(CC) -O0 -g $(SANFLAGS) -o debug_test debug_test.c check_password.c

# === Simple test run for password fuzzer ===
test: $(PASSWD_FUZZER)
	@echo "Testing with enhanced ASAN options..."
	ASAN_OPTIONS="detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:abort_on_error=1:print_stacktrace=1" ./$(PASSWD_FUZZER) -max_len=50 -runs=10

# === Cleanup ===
clean:
	rm -f $(PASSWD_FUZZER) $(DVCP_FUZZER) $(LIBSO) $(DVCP_SO) *.o crash-* oom-* timeout-* debug_test
	rm -rf *.dSYM
