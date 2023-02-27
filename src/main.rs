use playground::{ethereum, arweave};

fn main() {
    println!("testing // ethereum:");
    ethereum::test_eth(); // done@20230207
    println!("--------------------");

    println!("testing // arweave:");
    arweave::test_ar();
    println!("--------------------");
}
