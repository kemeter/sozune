//! e2e http-wasm guest. Two behaviours, both observable with curl:
//! - adds response header `x-wasm-plugin: ran` on every request
//! - if the request carries header `x-wasm-block: yes`, short-circuits with 403

#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}

const REQUEST: i32 = 0;
const RESPONSE: i32 = 1;

#[link(wasm_import_module = "http_handler")]
unsafe extern "C" {
    fn get_header_values(kind: i32, name: i32, name_len: i32, buf: i32, buf_limit: i32) -> i64;
    fn add_header_value(kind: i32, name: i32, name_len: i32, value: i32, value_len: i32);
    fn set_status_code(status: i32);
    fn write_body(kind: i32, body: i32, body_len: i32);
}

static mut SCRATCH: [u8; 256] = [0; 256];

#[unsafe(no_mangle)]
pub extern "C" fn handle_request() -> i64 {
    let name = b"x-wasm-block";
    let blocked = unsafe {
        let scratch = core::ptr::addr_of_mut!(SCRATCH) as *mut u8;
        let res = get_header_values(
            REQUEST,
            name.as_ptr() as i32,
            name.len() as i32,
            scratch as i32,
            256,
        );
        let len = (res & 0xffff_ffff) as usize;
        let bytes = core::slice::from_raw_parts(scratch, len);
        bytes.starts_with(b"yes")
    };

    if blocked {
        unsafe {
            set_status_code(403);
            let body = b"blocked by wasm plugin";
            write_body(RESPONSE, body.as_ptr() as i32, body.len() as i32);
        }
        return 0; // next = 0 => stop
    }

    unsafe {
        let hname = b"x-wasm-plugin";
        let hval = b"ran";
        add_header_value(
            RESPONSE,
            hname.as_ptr() as i32,
            hname.len() as i32,
            hval.as_ptr() as i32,
            hval.len() as i32,
        );
    }
    1 // next = 1 => continue
}

#[unsafe(no_mangle)]
pub extern "C" fn handle_response(_req_ctx: i32, _is_error: i32) {}
