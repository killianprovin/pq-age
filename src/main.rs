fn main() {
    let key: [u8; 32] = rand::random();

    println!("Generated key: {:?}", key);
}
