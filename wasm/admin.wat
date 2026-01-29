;; admin.wasm - Credential validator with XOR-encrypted credentials
;; Contains the actual admin credentials encrypted with XOR key
(module
  ;; Memory layout:
  ;; 0x00-0x09: XOR-encrypted username "superadmin" (10 bytes)
  ;; 0x10-0x1B: XOR-encrypted password "fl4g_hunt3r!" (12 bytes)
  ;; 0x20: XOR key (0x5A)
  ;; 0x100+: User input buffer
  
  (memory (export "memory") 1)
  
  ;; XOR-encrypted "superadmin" with key 0x5A:
  ;; s=0x73^0x5A=0x29, u=0x75^0x5A=0x2F, p=0x70^0x5A=0x2A, e=0x65^0x5A=0x3F
  ;; r=0x72^0x5A=0x28, a=0x61^0x5A=0x3B, d=0x64^0x5A=0x3E, m=0x6D^0x5A=0x37
  ;; i=0x69^0x5A=0x33, n=0x6E^0x5A=0x34
  (data (i32.const 0x00) "\29\2F\2A\3F\28\3B\3E\37\33\34")
  
  ;; XOR-encrypted "fl4g_hunt3r!" with key 0x5A:
  ;; f=0x66^0x5A=0x3C, l=0x6C^0x5A=0x36, 4=0x34^0x5A=0x6E, g=0x67^0x5A=0x3D
  ;; _=0x5F^0x5A=0x05, h=0x68^0x5A=0x32, u=0x75^0x5A=0x2F, n=0x6E^0x5A=0x34
  ;; t=0x74^0x5A=0x2E, 3=0x33^0x5A=0x69, r=0x72^0x5A=0x28, !=0x21^0x5A=0x7B
  (data (i32.const 0x10) "\3C\36\6E\3D\05\32\2F\34\2E\69\28\7B")
  
  ;; XOR key stored at offset 0x20
  (data (i32.const 0x20) "\5A")
  
  ;; Username length
  (global $username_len i32 (i32.const 10))
  
  ;; Password length  
  (global $password_len i32 (i32.const 12))
  
  ;; Get XOR key from memory
  (func $get_xor_key (result i32)
    (i32.load8_u (i32.const 0x20))
  )
  
  ;; XOR decrypt a byte
  (func $xor_byte (param $byte i32) (result i32)
    (i32.xor (local.get $byte) (call $get_xor_key))
  )
  
  ;; Compare input username with stored encrypted username
  ;; Returns 1 if match, 0 otherwise
  (func $check_username (param $input_ptr i32) (param $input_len i32) (result i32)
    (local $i i32)
    (local $encrypted_byte i32)
    (local $input_byte i32)
    (local $decrypted_byte i32)
    
    ;; Check length first
    (if (i32.ne (local.get $input_len) (global.get $username_len))
      (then (return (i32.const 0)))
    )
    
    ;; Compare each byte
    (local.set $i (i32.const 0))
    (block $break
      (loop $continue
        ;; Exit if we've checked all bytes
        (br_if $break (i32.ge_u (local.get $i) (global.get $username_len)))
        
        ;; Get encrypted byte and decrypt it
        (local.set $encrypted_byte (i32.load8_u (local.get $i)))
        (local.set $decrypted_byte (call $xor_byte (local.get $encrypted_byte)))
        
        ;; Get input byte
        (local.set $input_byte 
          (i32.load8_u (i32.add (local.get $input_ptr) (local.get $i))))
        
        ;; Compare
        (if (i32.ne (local.get $decrypted_byte) (local.get $input_byte))
          (then (return (i32.const 0)))
        )
        
        ;; Increment counter
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )
    
    (i32.const 1)
  )
  
  ;; Compare input password with stored encrypted password
  ;; Returns 1 if match, 0 otherwise
  (func $check_password (param $input_ptr i32) (param $input_len i32) (result i32)
    (local $i i32)
    (local $encrypted_byte i32)
    (local $input_byte i32)
    (local $decrypted_byte i32)
    
    ;; Check length first
    (if (i32.ne (local.get $input_len) (global.get $password_len))
      (then (return (i32.const 0)))
    )
    
    ;; Compare each byte (password starts at offset 0x10)
    (local.set $i (i32.const 0))
    (block $break
      (loop $continue
        ;; Exit if we've checked all bytes
        (br_if $break (i32.ge_u (local.get $i) (global.get $password_len)))
        
        ;; Get encrypted byte from offset 0x10 and decrypt it
        (local.set $encrypted_byte 
          (i32.load8_u (i32.add (i32.const 0x10) (local.get $i))))
        (local.set $decrypted_byte (call $xor_byte (local.get $encrypted_byte)))
        
        ;; Get input byte
        (local.set $input_byte 
          (i32.load8_u (i32.add (local.get $input_ptr) (local.get $i))))
        
        ;; Compare
        (if (i32.ne (local.get $decrypted_byte) (local.get $input_byte))
          (then (return (i32.const 0)))
        )
        
        ;; Increment counter
        (local.set $i (i32.add (local.get $i) (i32.const 1)))
        (br $continue)
      )
    )
    
    (i32.const 1)
  )
  
  ;; Main validate function - exported for JS
  ;; Returns 1 if credentials are valid, 0 otherwise
  (func (export "validate") 
    (param $username_ptr i32) 
    (param $username_len i32)
    (param $password_ptr i32)
    (param $password_len i32)
    (result i32)
    
    ;; Both username and password must match
    (if (i32.eqz (call $check_username (local.get $username_ptr) (local.get $username_len)))
      (then (return (i32.const 0)))
    )
    
    (if (i32.eqz (call $check_password (local.get $password_ptr) (local.get $password_len)))
      (then (return (i32.const 0)))
    )
    
    (i32.const 1)
  )
)
