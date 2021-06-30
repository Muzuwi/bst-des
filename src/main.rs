use std::path::Path;
use std::fs::File;
use std::borrow::{BorrowMut, Borrow};
use std::io::{Read, Write};

mod des;


struct CmdArguments {
    input_file: Option<String>,
    output_file: Option<String>,
    key_file: Option<String>,
    decrypt: bool
}


fn parse_arguments(args: Vec<String>) -> Option<CmdArguments> {
    if args.len() < 2 {
        println!("Not enough arguments");
        println!("Usage:");
        println!("\t-i <filename>\t\tFile to encrypt/decrypt");
        println!("\t-o <filename>\t\tEncryption/decryption output filename");
        println!("\t-k <filename>\t\tKey filename");
        println!("\t-e\t\tEncrypt file (default option)");
        println!("\t-d\t\tDecrypt file");
        return None
    }

    let mut prog_args: CmdArguments = CmdArguments {
        input_file: None,
        output_file: None,
        key_file: None,
        decrypt: false
    };

    let mut i = 1;
    loop {
        if i >= args.len() {
            break;
        }

        let arg = &args[i];
        let has_parameter = (i+1) < args.len();

        match arg.as_ref() {
            "-i" => {
                if !has_parameter {
                    println!("Missing parameter: input_filename");
                    return None
                }

                let filename = &args[i+1];
                prog_args.input_file = Some(filename.clone());

                i += 2;
            }
            "-o" => {
                if !has_parameter {
                    println!("Missing parameter: output_filename");
                    return None
                }

                let filename = &args[i+1];
                prog_args.output_file = Some(filename.clone());

                i += 2;
            }
            "-k" => {
                if !has_parameter {
                    println!("Missing parameter: key_filename");
                    return None
                }

                let filename = &args[i+1];
                prog_args.key_file = Some(filename.clone());

                i += 2;
            }
            "-e"|"-d" => {
                prog_args.decrypt = (arg == "-d");

                i += 1;
            }
            _ => {
                println!("Unknown argument '{}'", arg);
                return None
            }
        }
    }


    if prog_args.input_file.is_none() {
        println!("Missing argument: file to encrypt");
        return None
    }
    if prog_args.output_file.is_none() {
        println!("Missing argument: output filename");
        return None
    }
    if prog_args.key_file.is_none() {
        println!("Missing argument: key file filename");
        return None
    }

    return Some(prog_args)
}

fn load_file_bytes(path: String) -> Option<Vec<u8>> {
    let mut file = File::open(Path::new(path.as_str()));
    if file.is_err() {
        println!("Failed opening file '{}': {}", path, file.err().unwrap());
        return None
    }
    let mut file = file.unwrap();

    let mut vec: Vec<u8> = Vec::new();
    let s = file.read_to_end(vec.borrow_mut());
    if s.is_err() {
        println!("Failed reading from file '{}': {}", path, s.err().unwrap());
        return None
    }

    return Some(vec)
}

fn write_file_bytes(path: String, bytes: &Vec<u8>) {
    let mut file = File::create(&path);
    if file.is_err() {
        println!("Failed creating file '{}': {}", path, file.err().unwrap());
        return
    }
    let mut file = file.unwrap();

    let res = file.write_all(bytes);
    if res.is_err() {
        println!("Failed writing to file '{}': {}", path, res.err().unwrap());
    }
}


fn main() {
    let args: Vec<String> = std::env::args().collect();
    let params = parse_arguments(args);
    if params.is_none() {
        return
    }
    let params = params.unwrap();

    let input_file = load_file_bytes(params.input_file.unwrap()).unwrap();
    let key_file = load_file_bytes(params.key_file.unwrap()).unwrap();

    let output: Vec<u8>;
    if params.decrypt {
        output = des::decrypt_vec(input_file.borrow(), key_file.borrow());
    } else {
        output = des::encrypt_vec(input_file.borrow(), key_file.borrow());
    }
    write_file_bytes(params.output_file.unwrap(), output.borrow());
}
