mod constants;

use std::borrow::{BorrowMut, Borrow};
use bitvec::order::Msb0;
use bitvec::slice::BitSlice;


#[derive(Copy, Clone, Debug)]
pub struct Key {
    key: u64,
    round_keys: [u64; 16],
}


impl Key {
    fn shifts_for_round(rounds: u32) -> u8 {
        return match rounds {
            1 | 2 | 9 | 16 => 1,
            _ => 2
        };
    }


    /*
        Obraca wejściowy klucz (lewą/prawą część) @count razy
     */
    fn rotate_cd(input: u64, count: u8) -> u64 {
        let mut left = (input >> 28) & 0xFFFFFFF;
        let mut right = (input) & 0xFFFFFFF;

        left = left.rotate_left(count as u32);
        right = right.rotate_left(count as u32);

        left = ((left >> 28) | (left & 0xFFFFFFF)) & 0xFFFFFFF;
        right = ((right >> 28) | (right & 0xFFFFFFF)) & 0xFFFFFFF;

        return (left << 28) | right;
    }


    /*
        Wykonuje operacje PC1 na wejściowym kluczu
     */
    fn permuted_choice1(key: u64) -> u64 {
        let key_bits: &BitSlice<Msb0, u64> = BitSlice::from_element(key.borrow());

        let mut output: u64 = 0;
        let mut data_bits: &mut BitSlice<Msb0, u64> = BitSlice::from_element_mut(output.borrow_mut());
        for i in 0..56 {
            data_bits.set(i, key_bits[(crate::des::constants::PC1[i] - 1) as usize]);
        }
        output >>= 8;

        return output;
    }


    /*
        Wykonuje operacje PC2 na wejściowym kluczu
     */
    fn permuted_choice2(key: u64) -> u64 {
        let mut round_key: u64 = 0;
        let mut rkey_bits: &mut BitSlice<Msb0, u64> = BitSlice::from_element_mut(round_key.borrow_mut());

        let shifted_key = key << 8;
        let shift_bits: &BitSlice<Msb0, u64> = BitSlice::from_element(shifted_key.borrow());

        for i in 0..48 {
            rkey_bits.set(i, shift_bits[(crate::des::constants::PC2[i] - 1) as usize]);
        }
        round_key >>= 16;

        return round_key;
    }


    /*
        Generacja kluczy rund dla wejściowego klucza
     */
    fn generate_round_keys(main_key: u64) -> [u64; 16] {
        let mut round_keys: [u64; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        let mut current_key = main_key;
        for round in 1..=16 {
            let shifts = Key::shifts_for_round(round);
            current_key = Key::rotate_cd(current_key, shifts as u8);
            let rkey = Key::permuted_choice2(current_key);

            round_keys[(round - 1) as usize] = rkey;
        }

        return round_keys;
    }


    /*  ===========
        Konstruktory
        =========== */
    fn from_u64(key: u64) -> Key {
        let permuted = Key::permuted_choice1(key);
        // println!("After PC1: {:016x}", permuted);

        return Key {
            key: permuted,
            round_keys: Key::generate_round_keys(permuted),
        };
    }

    fn from_bytes(bytes: &[u8]) -> Key {
        let mut key: u64 = 0;
        for i in 0..8 {
            key <<= 8;
            let byte;
            if i < bytes.len() {
                byte = bytes[i];
            } else {
                byte = 0;
            }
            key = key | byte as u64;
        }

        return Key::from_u64(key);
    }


    //  Zwraca klucz rundy dla danej rundy
    fn round_key(&self, round: u8) -> Option<u64> {
        if round >= 16 {
            return None;
        }

        return Some(self.round_keys[round as usize]);
    }
}


#[derive(Copy, Clone, Debug)]
pub struct Block {
    data: u64,
}


impl Block {
    /*
        Utworzenie bloku z lewej i prawej części (górnych i dolnych 32-bitów)
     */
    fn from_parts(left: u32, right: u32) -> Block {
        Block {
            data: ((left as u64) << 32) | (right as u64)
        }
    }


    fn from_u64(data: u64) -> Block {
        Block {
            data: data
        }
    }

    /*
        Utworzenie bloku z sekwencji bajtów.
        Jeżeli długość sekwencji na wejściu jest mniejsza od 8, pozostałe bajty
        są uzupełniane zerami
     */
    fn from_bytes(bytes: &[u8]) -> Block {
        let mut data: u64 = 0;

        for i in 0..8 {
            data <<= 8;
            let byte: u8;
            //  Padding zerami
            if i >= bytes.len() {
                byte = 0;
            } else {
                byte = bytes[i];
            }
            data = data | byte as u64;
        }

        return Block {
            data: data
        };
    }


    /*
        Wykonywanie permutacji wstępnej na bloku
     */
    fn initial_permutation(&mut self) {
        let original_block = self.data.clone();
        let original: &BitSlice<Msb0, u64> = BitSlice::from_element(&original_block);

        //  Wykonaj permutację wstępną
        let mut bits: &mut BitSlice<Msb0, u64> = BitSlice::from_element_mut(&mut self.data);
        for i in 0..64 {
            bits.set(i, original[(crate::des::constants::IP[i] - 1) as usize]);
        }
    }


    /*
        Wykonywanie permutacji końcowej na bloku
     */
    fn final_permutation(&mut self) {
        let original_block = self.data.clone();
        let original: &BitSlice<Msb0, u64> = BitSlice::from_element(&original_block);

        //  Wykonaj permutację wstępną
        let mut bits: &mut BitSlice<Msb0, u64> = BitSlice::from_element_mut(&mut self.data);
        for i in 0..64 {
            bits.set(i, original[(crate::des::constants::FP[i] - 1) as usize]);
        }
    }


    /*
        Lewa część bloku (górne 32 bity)
     */
    fn left(&self) -> u32 {
        (self.data >> 32) as u32
    }


    /*
        Prawa część bloku (dolne 32 bity)
    */
    fn right(&self) -> u32 {
        (self.data & 0xFFFFFFFF) as u32
    }


    fn des_run(&mut self, key: &Key, is_decrypt: bool) {
        // println!("Input: {:016x}", self.data);

        self.initial_permutation();

        // println!("After IP: {:016x}", self.data);

        for i in 1..=16 {
            let which_key: u8;
            if is_decrypt {
                which_key = (16 - i)
            } else {
                which_key = i - 1;
            }

            let round_key = key.round_key(which_key).unwrap();

            let mut left_part = self.left();
            let right_part = self.right();
            let ffunc_output = Block::ffunc(right_part, round_key);

            left_part = left_part ^ ffunc_output;

            *self = Block::from_parts(right_part, left_part);

            if i == 16 {
                *self = Block::from_parts(self.right(), self.left());
            }

            // println!("Round {:02}: L={:08x} R={:08x} Kround={:012x}", i, self.left(), self.right(), round_key);
        }

        self.final_permutation();

        // println!("After FP: {:016x}", self.data);
    }

    fn crypt(&mut self, key: &Key) {
        self.des_run(key, false);
    }

    fn decrypt(&mut self, key: &Key) {
        self.des_run(key, true);
    }


    //  Poszerzenie wejścia
    fn expand(input: u32) -> u64 {
        let input_bits: &BitSlice<Msb0, u32> = BitSlice::from_element(input.borrow());

        let mut output: u64 = 0;
        let mut output_bits: &mut BitSlice<Msb0, u64> = BitSlice::from_element_mut(output.borrow_mut());
        for i in 0..48 {
            output_bits.set(i, input_bits[(crate::des::constants::E[i] - 1) as usize]);
        }
        output >>= 16;

        return output;
    }


    //  Wartość sboxu @which o podanym kodzie @code
    fn sbox(code: u8, which: u8) -> u8 {
        let row = ((code >> 4) & 0b10) | (code & 1);
        let col = (code >> 1) & 0xF;
        let val = crate::des::constants::SBOXES[which as usize][(row * 16 + col) as usize];

        // println!("which={} code={:06b} row={} col={} val={}", which+1, code, row, col, val);
        return val;
    }


    //  Dokonuje przekształcenia wejścia za pomocą sboxów
    fn sbox_substitution(input: u64) -> u32 {
        const MASK: u64 = (0x3F);

        let mut output: u32 = 0;
        for i in (0..8).rev() {
            output <<= 4;

            let code = ((input >> (i * 6)) & MASK) as u8;
            let sbox_output = Block::sbox(code, (7 - i) as u8);
            output |= sbox_output as u32;
        }

        return output;
    }


    //  Przekształcenie wejścia macierzą P
    fn permute(input: u32) -> u32 {
        let input_bits: &BitSlice<Msb0, u32> = BitSlice::from_element(input.borrow());

        let mut output: u32 = 0;
        let mut output_bits: &mut BitSlice<Msb0, u32> = BitSlice::from_element_mut(output.borrow_mut());

        for i in 0..32 {
            output_bits.set(i, input_bits[(crate::des::constants::P[i] - 1) as usize]);
        }

        return output;
    }


    //  Funkcja F pojedynczej rundy DES
    fn ffunc(rmin: u32, round_key: u64) -> u32 {
        let expanded: u64 = Block::expand(rmin);
        let xored: u64 = expanded ^ round_key;
        let sbox_output = Block::sbox_substitution(xored);
        let permuted = Block::permute(sbox_output);

        // println!("Expanded={:012x}, xor={:012x}, sbox_out={:08x}, permute={:08x}", expanded, xored, sbox_output, permuted);

        return permuted;
    }
}


/*
    Tworzy wektor bloków 8-bajtowych z wejściowego wektora bajtów
    Bloki są następnie wykorzystywane przy szyfrowaniu
 */
fn plaintext_create_blocks(plaintext: &Vec<u8>) -> Vec<Block> {
    let mut output_blocks: Vec<Block> = Vec::new();

    //  Bierzemy po 8 bajtów z wektora wejściowego
    for bytes in plaintext.chunks(8) {
        output_blocks.push(Block::from_bytes(&bytes));
    }

    return output_blocks;
}

fn create_key_vec(key_stream: &Vec<u8>) -> Vec<Key> {
    let mut keys: Vec<Key> = Vec::new();

    for bytes in key_stream.chunks(8) {
        keys.push(Key::from_bytes(bytes));
    }

    return keys;
}

fn des_run_vec(data: &Vec<u8>, key_stream: &Vec<u8>, do_decrypt: bool) -> Vec<u8> {
    let mut data_blocks = plaintext_create_blocks(data);
    let keys = create_key_vec(key_stream);

    if key_stream.len() % 8 != 0 {
        println!("WARNING: Key stream not a multiple of 8. Keys will be padded with zeros.");
    }

    if data_blocks.len() > keys.len() {
        println!("WARNING: Not enough keys for {} whole file!", match do_decrypt {
            true => "decrypting",
            false => "encrypting"
        });
        println!("WARNING: Keys will be reused!");
    }

    for i in 0..data_blocks.len() {
        let which_key = i % keys.len();
        if do_decrypt {
            data_blocks[i].decrypt(keys[which_key].borrow());
        } else {
            data_blocks[i].crypt(keys[which_key].borrow());
        }
    }

    let mut output_vector: Vec<u8> = Vec::new();
    for block in data_blocks {
        let bytes = block.data.to_be_bytes();
        output_vector.extend(&bytes);
    }

    return output_vector;
}

pub fn encrypt_vec(plaintext: &Vec<u8>, key_stream: &Vec<u8>) -> Vec<u8> {
    return des_run_vec(plaintext, key_stream, false);
}

pub fn decrypt_vec(plaintext: &Vec<u8>, key_stream: &Vec<u8>) -> Vec<u8> {
    return des_run_vec(plaintext, key_stream, true);
}

/* ===================================
      Testy działania implementacji
   =================================== */

macro_rules! assert_data_eq {
        ($left: expr, $right: expr) => {
            assert_eq!($left, $right, "Invalid cipherblock! Got {:#016x} vs expected {:#016x}", $left, $right);
        };
    }

/*
    Test permutacji wstępnej na bloku danych
 */
#[test]
fn test_block_permutation() {
    let mut block = Block { data: 0x0002000000000001 };
    block.initial_permutation();
    assert_eq!(block.data, 0x0000008000000002, "Invalid data permutation! {:0x} != {:0x}", block.data, 0x0000008000000002 as u64);

    block = Block { data: 0x675a69675e5a6b5a };
    block.initial_permutation();
    assert_eq!(block.data, 0xffb2194d004df6fb, "Invalid data permutation! {:0x} != {:0x}", block.data, 0xffb2194d004df6fb as u64);
}


/*
    Test tworzenia bloku z wektora bajtów
 */
#[test]
fn test_block_creation() {
    const TEMP: [u8; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
    let vec: Vec<u8> = Vec::from(&TEMP[0..12]);
    let blocks = plaintext_create_blocks(&vec);

    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].data, 0x0001020304050607);
    assert_eq!(blocks[1].data, 0x08090a0b00000000);
}


/*
    Testy bloku danych
 */
#[test]
fn test_block_ip_1() {
    let mut message = Block::from_u64(0x123456ABCD132536);
    message.initial_permutation();
    assert_data_eq!(message.data, 0x14A7D67818CA18ADu64);
}

#[test]
fn test_block_ip_2() {
    let mut message = Block::from_u64(0xC0B7A8D05F3A829C);
    message.initial_permutation();
    assert_data_eq!(message.data, 0x19BA9212CF26B472u64);
}

#[test]
fn test_block_ip_3() {
    let mut message = Block::from_u64(0b0000000100100011010001010110011110001001101010111100110111101111);
    message.initial_permutation();
    assert_data_eq!(message.data, 0b1100110000000000110011001111111111110000101010101111000010101010u64);
}

#[test]
fn test_block_fp_1() {
    let mut message = Block::from_u64(0x14A7D67818CA18AD);
    message.final_permutation();
    assert_data_eq!(message.data, 0x123456ABCD132536u64);
}

#[test]
fn test_block_lr() {
    let mut message = Block::from_u64(0b1100110000000000110011001111111111110000101010101111000010101010);
    assert_data_eq!(message.left(), 0b11001100000000001100110011111111 as u32);
    assert_data_eq!(message.right(), 0b11110000101010101111000010101010 as u32);
}


/*
    Testy klucza
 */

#[test]
fn test_key_pc1() {
    let key: Key = Key::from_u64(0x5b5a57676a56676e);
    assert_data_eq!(key.key, 0x00ffd82ffec937u64);
}

#[test]
fn test_key_pc1_weak_01() {
    let mut key = Key::from_u64(0x0101010101010101);
    assert_eq!(key.key, 0x0);
}

#[test]
fn test_key_pc1_weak_1f0e() {
    let key = Key::from_u64(0x1f1f1f1f0e0e0e0e);
    assert_eq!(key.key, 0x000000000fffffff);
}

#[test]
fn test_key_pc1_weak_e0f1() {
    let key = Key::from_u64(0xe0e0e0e0f1f1f1f1);
    assert_eq!(key.key, 0x00fffffff0000000);
}

#[test]
fn test_key_pc1_weak_fefe() {
    let key = Key::from_u64(0xfefefefefefefefe);
    assert_eq!(key.key, 0x00ffffffffffffff);
}

#[test]
fn test_key_pc1_2() {
    let key = Key::from_u64(0b0001001100110100010101110111100110011011101111001101111111110001);
    assert_data_eq!(key.key, 0b11110000110011001010101011110101010101100110011110001111u64);
}

#[test]
fn test_key_rotate_cd() {
    let mut permuted_key = 0b11110000110011001010101011110101010101100110011110001111;
    const RGOOD: [u64; 16] = [
        0b11100001100110010101010111111010101011001100111100011110u64,
        0b11000011001100101010101111110101010110011001111000111101u64,
        0b00001100110010101010111111110101011001100111100011110101u64,
        0b00110011001010101011111111000101100110011110001111010101u64,
        0b11001100101010101111111100000110011001111000111101010101u64,
        0b00110010101010111111110000111001100111100011110101010101u64,
        0b11001010101011111111000011000110011110001111010101010110u64,
        0b00101010101111111100001100111001111000111101010101011001u64,
        0b01010101011111111000011001100011110001111010101010110011u64,
        0b01010101111111100001100110011111000111101010101011001100u64,
        0b01010111111110000110011001011100011110101010101100110011u64,
        0b01011111111000011001100101010001111010101010110011001111u64,
        0b01111111100001100110010101010111101010101011001100111100u64,
        0b11111110000110011001010101011110101010101100110011110001u64,
        0b11111000011001100101010101111010101010110011001111000111u64,
        0b11110000110011001010101011110101010101100110011110001111u64,
    ];

    println!("R00: {:064b}", permuted_key);
    for i in 1..=16 {
        permuted_key = Key::rotate_cd(permuted_key, Key::shifts_for_round(i));

        println!("R{:02}: {:064b}", i, permuted_key);
        println!("  vs {:064b}", RGOOD[(i - 1) as usize]);
        assert_data_eq!(permuted_key, RGOOD[(i-1) as usize]);
    }
}

#[test]
fn test_key_round_gen() {
    let mut key = Key::from_u64(0b0001001100110100010101110111100110011011101111001101111111110001);

    const RKEYS: [u64; 16] = [
        0b000110110000001011101111111111000111000001110010u64,
        0b011110011010111011011001110110111100100111100101u64,
        0b010101011111110010001010010000101100111110011001u64,
        0b011100101010110111010110110110110011010100011101u64,
        0b011111001110110000000111111010110101001110101000u64,
        0b011000111010010100111110010100000111101100101111u64,
        0b111011001000010010110111111101100001100010111100u64,
        0b111101111000101000111010110000010011101111111011u64,
        0b111000001101101111101011111011011110011110000001u64,
        0b101100011111001101000111101110100100011001001111u64,
        0b001000010101111111010011110111101101001110000110u64,
        0b011101010111000111110101100101000110011111101001u64,
        0b100101111100010111010001111110101011101001000001u64,
        0b010111110100001110110111111100101110011100111010u64,
        0b101111111001000110001101001111010011111100001010u64,
        0b110010110011110110001011000011100001011111110101u64,
    ];

    for i in 1..=16 {
        let round_key = key.round_key(i - 1).unwrap();
        println!("R{:02}: {:048b}", i, round_key);
        println!("  vs {:048b}", RKEYS[(i - 1) as usize]);

        assert_data_eq!(round_key, RKEYS[(i-1) as usize]);
    }
}


/*
    Testy samego algorytmu szyfrowania
 */

#[test]
fn test_block_decrypt() {
    let mut key = Key::from_u64(0x0101010101010101);
    let mut message = Block::from_u64(0x8787878787878787);

    message.crypt(key.borrow());

    key = Key::from_u64(0x0101010101010101);
    message.crypt(key.borrow());
    let plain = message.data;

    assert_eq!(plain, 0x8787878787878787);
}

#[test]
fn test_crypt_zeros() {
    let mut key = Key::from_u64(0x0);
    let mut message = Block::from_u64(0x0);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0x8CA64DE9C1B123A7u64);
}

#[test]
fn test_crypt_ones() {
    let mut key = Key::from_u64(0xFFFFFFFFFFFFFFFF);
    let mut message = Block::from_u64(0xFFFFFFFFFFFFFFFF);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0x7359B2163E4EDC58u64);
}

#[test]
fn test_crypt_pat1() {
    let mut key = Key::from_u64(0x1111111111111111);
    let mut message = Block::from_u64(0x1111111111111111);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0xF40379AB9E0EC533u64);
}

#[test]
fn test_crypt_pat2() {
    let mut key = Key::from_u64(0x0123456789ABCDEF);
    let mut message = Block::from_u64(0x1111111111111111);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0x17668DFC7292532Du64);
}

#[test]
fn test_crypt_pat3() {
    let mut key = Key::from_u64(0x1111111111111111);
    let mut message = Block::from_u64(0x0123456789ABCDEF);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0x8A5AE1F81AB8F2DDu64);
}

#[test]
fn test_crypt_pat4() {
    let mut key = Key::from_u64(0xFEDCBA9876543210);
    let mut message = Block::from_u64(0x0123456789ABCDEF);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0xED39D950FA74BCC4u64);
}

#[test]
fn test_crypt_pat5() {
    let mut key = Key::from_u64(0x7CA110454A1A6E57);
    let mut message = Block::from_u64(0x01A1D6D039776742);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0x690F5B0D9A26939Bu64);
}

#[test]
fn test_crypt_6() {
    let mut key = Key::from_u64(0xAABB09182736CCDD);
    let mut message = Block::from_u64(0xC0B7A8D05F3A829C);
    message.decrypt(key.borrow());
    assert_data_eq!(message.data, 0x123456ABCD132536u64);
}

#[test]
fn test_crypt_7() {
    let mut key = Key::from_u64(0xAA11BB22CC33DD44);
    let mut message = Block::from_u64(0x0102030405060708);
    message.crypt(key.borrow());
    assert_data_eq!(message.data, 0xd6196fcdf536f2e8u64);
}

#[test]
fn test_crypt_7_de() {
    let mut key = Key::from_u64(0xAA11BB22CC33DD44);
    let mut message = Block::from_u64(0xd6196fcdf536f2e8);
    message.decrypt(key.borrow());
    assert_data_eq!(message.data, 0x0102030405060708u64);
}
