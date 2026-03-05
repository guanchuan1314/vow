pub fn dangerous_unsafe_operations() {
    unsafe {
        // Use after free pattern
        let ptr = Box::into_raw(Box::new(42));
        drop(Box::from_raw(ptr));
        println!("{}", *ptr);  // Use after free
        
        // Double free pattern
        let ptr2 = Box::into_raw(Box::new(100));
        drop(Box::from_raw(ptr2));
        drop(Box::from_raw(ptr2));  // Double free
        
        // Buffer overflow pattern
        let mut buffer = [0u8; 10];
        let ptr = buffer.as_mut_ptr();
        *ptr.offset(20) = 42;  // Buffer overflow
        
        // Uninitialized memory
        let mut uninit: std::mem::MaybeUninit<i32> = std::mem::MaybeUninit::uninit();
        let value = uninit.assume_init();  // Using uninitialized memory
        
        // Integer overflow in unsafe
        let large_num: u8 = 255;
        let overflow = large_num + 1;  // Potential overflow
        
        // Transmute type confusion
        let data: [u8; 4] = [1, 2, 3, 4];
        let int_val: i32 = std::mem::transmute(data);  // Type confusion
    }
}