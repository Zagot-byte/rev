;; user.wasm - Decoy validator (always returns 0)
;; This is the default validator loaded by login.js
(module
  ;; Memory export for JS interaction
  (memory (export "memory") 1)
  
  ;; Validate function - always returns 0 (invalid)
  ;; Players should notice this always fails and look for alternatives
  (func (export "validate") 
    (param $username_ptr i32) 
    (param $username_len i32)
    (param $password_ptr i32)
    (param $password_len i32)
    (result i32)
    
    ;; Always return 0 - no valid credentials in this module
    (i32.const 0)
  )
)
