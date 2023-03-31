use playground::{arweave, ethereum, solana};// polkadot, stacks

fn main() {
    println!("testing // ethereum:");
    ethereum::test(); // done@20230207
    println!("--------------------");

    println!("testing // arweave:");
    arweave::test(); // done@20230227
    println!("--------------------");

    println!("testing // solana:");
    solana::test(); // done@20230331
    println!("--------------------");
    
    // println!("testing // polkadot:");
    // polkadot::test(); //
    // println!("--------------------");

    // println!("testing // stacks:");
    // stacks::test(); //
    // println!("--------------------");

}
