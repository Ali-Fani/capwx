//! Spike: the vendored HashWX C library as a standalone shared library, loaded with `ctypes`.
//!
//! This is the shape a native HashWX path would take without a Python extension: the LGPL code
//! stays a separate, replaceable binary (like `hashwx.wasm` today), the loader is plain `ctypes`,
//! and there is no CPython ABI to build against. See `../../docs/native-code-evaluation.md`.

#[repr(C)]
pub struct Ctx {
    _private: [u8; 0],
}

extern "C" {
    fn hashwx_alloc(kind: i32) -> *mut Ctx;
    fn hashwx_make(ctx: *mut Ctx, seed: *const u8);
    fn hashwx_exec(ctx: *const Ctx, input: u64) -> u64;
    fn hashwx_free(ctx: *mut Ctx);
}

/// `hashwx_type`: 0 = interpreted, 1 = compiled (JIT to native code).
#[no_mangle]
pub unsafe extern "C" fn capwx_hashwx_alloc(kind: i32) -> *mut Ctx {
    unsafe { hashwx_alloc(kind) }
}

#[no_mangle]
pub unsafe extern "C" fn capwx_hashwx_make(ctx: *mut Ctx, seed: *const u8) {
    unsafe { hashwx_make(ctx, seed) }
}

#[no_mangle]
pub unsafe extern "C" fn capwx_hashwx_exec(ctx: *const Ctx, input: u64) -> u64 {
    unsafe { hashwx_exec(ctx, input) }
}

#[no_mangle]
pub unsafe extern "C" fn capwx_hashwx_free(ctx: *mut Ctx) {
    unsafe { hashwx_free(ctx) }
}
