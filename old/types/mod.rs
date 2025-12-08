mod ffi;
mod rust;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct CSlice {
    pub ptr: *const u8,
    pub len: usize,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RustSlice {
    pub ptr: *const u8,
    pub len: usize,
    pub cap: usize,
}

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Error(CSlice);

#[repr(transparent)]
#[derive(Copy, Clone, Debug, Default)]
pub struct RustError(pub RustSlice);

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Key {
    pub bytes: [u8; 32],
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct Nonce {
    pub bytes: [u8; 24],
}
