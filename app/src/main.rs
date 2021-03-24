#![feature(toowned_clone_into)]
#[cfg(test)]
extern crate mockall;
extern crate mockall_double;
#[cfg(test)]
extern crate num_traits;
#[cfg(test)]
extern crate proptest;
#[cfg(test)]
extern crate rand;
extern crate rsa;
extern crate sgx_types;
extern crate sgx_urts;
extern crate thiserror;
use sgx_types::*;
use sgx_urts::SgxEnclave;

pub mod attestation;
pub mod rtc_enclave;

use rtc_enclave::RtcEnclave;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

extern "C" {
    fn say_something(
        eid: sgx_enclave_id_t,
        retval: *mut sgx_status_t,
        some_string: *const u8,
        len: usize,
    ) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {
        secs_attr: sgx_attributes_t { flags: 0, xfrm: 0 },
        misc_select: 0,
    };
    SgxEnclave::create(
        ENCLAVE_FILE,
        debug,
        &mut launch_token,
        &mut launch_token_updated,
        &mut misc_attr,
    )
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        }
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        }
    };

    println!("{:?}", enclave.create_report(&sgx_target_info_t::default()));

    let input_string = String::from("This is a normal world string passed into Enclave!\n");
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        say_something(
            enclave.geteid(),
            &mut retval,
            input_string.as_ptr() as *const u8,
            input_string.len(),
        )
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {}
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    println!("[+] say_something success...");
    enclave.destroy();
}
