/* This file excercises the ELF loader.
 */

#include "common.h"

char __license[] __section("license") = "MIT";

#if __clang_major__ >= 9
// Clang < 9 doesn't emit the necessary BTF for this to work.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, uint32_t);
	__type(value, uint64_t);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} hash_map __section(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(uint32_t));
	__uint(value_size, sizeof(uint64_t));
	__uint(max_entries, 2);
} hash_map2 __section(".maps");
#else
struct bpf_map_def hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 1,
	.map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def hash_map2 __section("maps") = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(uint32_t),
	.value_size  = sizeof(uint64_t),
	.max_entries = 2,
};
#endif

struct bpf_map_def array_of_hash_map __section("maps") = {
	.type        = BPF_MAP_TYPE_ARRAY_OF_MAPS,
	.key_size    = sizeof(uint32_t),
	.max_entries = 2,
};

static int __attribute__((noinline)) static_fn(uint32_t arg) {
	return arg;
}

int __attribute__((noinline)) global_fn2(uint32_t arg) {
	return arg++;
}

int __attribute__((noinline)) __section("other") global_fn3(uint32_t arg) {
	return arg + 1;
}

int __attribute__((noinline)) global_fn(uint32_t arg) {
	return static_fn(arg) + global_fn2(arg) + global_fn3(arg);
}

#if __clang_major__ >= 9
static volatile unsigned int key1       = 0; // .bss
static volatile unsigned int key2       = 1; // .data
static volatile const unsigned int key3 = 2; // .rodata
static volatile const uint32_t arg;          // .rodata, rewritten by loader
#endif

__section("xdp") int xdp_prog() {
#if __clang_major__ < 9
	unsigned int key1 = 0;
	unsigned int key2 = 1;
	unsigned int key3 = 2;
	uint32_t arg      = 1;
#endif
	map_lookup_elem(&hash_map, (void *)&key1);
	map_lookup_elem(&hash_map2, (void *)&key2);
	map_lookup_elem(&hash_map2, (void *)&key3);
	return static_fn(arg) + global_fn(arg);
}

// This function has no relocations, and is thus parsed differently.
__section("socket") int no_relocation() {
	return 0;
}
