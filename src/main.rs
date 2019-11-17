
extern crate clap;
extern crate glob;
extern crate pcap_file;
extern crate shellexpand;
extern crate regex;
extern crate hex;

use clap::{App, SubCommand, AppSettings};
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter, PcapHeader, DataLink};
use pcap_file::errors::Error;
use glob::glob;
use std::path::PathBuf;
use std::process::exit;
use std::io::{BufRead, BufReader, Write};
use regex::Regex;


fn merge_file(path: PathBuf, pcap_writer: &mut PcapWriter<File>) -> Result<(), Error> {
    let file_in = File::open(path)?;
    let pcap_reader = PcapReader::new(file_in)?;

    for pcap in pcap_reader {
        let pcap = pcap?;
        pcap_writer.write_packet(&pcap)?;
    }

    Ok(())
}

fn merge() {
    println!("Merging *.pcap files into /tmp/all.pcap");

    let file_out = File::create("/tmp/all.pcap").expect("Error creating file");

    let header = PcapHeader {
        magic_number : 0xa1b2c3d4,
        version_major : 2,
        version_minor : 4,
        ts_correction : 0,
        ts_accuracy : 0,
        snaplen : 65535,
        datalink : DataLink::IEEE802_11_RADIOTAP
    };

    let mut pcap_writer = PcapWriter::with_header(header, file_out).unwrap();

    for entry in glob("*.pcap").expect("Failed to get files") {
        match entry {
            Ok(path) => {
                println!("Merging file {:?}", path.display());
                match merge_file(path, &mut pcap_writer) {
                    Ok(_) => {},
                    Err(e) => println!("Failed to merge file: {:?}", e)
                }
            },
            Err(e) => println!("{:?}", e),
        }
    }

    println!("Merged *.pcap files into /tmp/all.pcap");
}

fn potfile() {
    println!("Parsing potfile");

    let potfile_path = shellexpand::tilde("~/.hashcat/hashcat.potfile");
    let potfile = File::open(potfile_path.as_ref()).expect("Failed to open potfile");
    let reader = BufReader::new(potfile);

    let mut networks_file = File::create("/tmp/networks.txt").expect("Failed to create /tmp/networks.txt");

    for line in reader.lines() {
        if let Ok(line) = line {
            // Creds cracked from .hccapx format
            let wifi_2500 = Regex::new("^[a-z0-9]{32}:[a-z0-9]{12}:[a-z0-9]{11}").unwrap();

            // Creds cracked from .pmkid format
            let wifi_16800 = Regex::new("^[a-z0-9]{32}\\*[a-z0-9]{12}\\*[a-z0-9]{11}").unwrap();
            
            if wifi_2500.is_match(&line) {
                let creds = get_creds_wifi_2500(&line);
                println!("Wifi {:>5}: {}", "2500", creds);
                networks_file.write_fmt(format_args!("{}\n", creds)).expect("Failed to write creds");
            } else if wifi_16800.is_match(&line) {
                let creds = get_creds_wifi_16800(&line);
                println!("Wifi {:>5}: {}", "16800", creds);
                networks_file.write_fmt(format_args!("{}\n", creds)).expect("Failed to write creds");
            } else {
                println!("Unknown");
                continue;
            }
        }
    }

    println!("Finished parsing potfile");
}

fn get_creds_wifi_2500(line: &str) -> String {
    let mut parts = line
        .split(":")
        .map(|s| s.to_owned())
        .collect::<Vec<_>>();

    parts.reverse();

    format!("{}:{}", parts[1], parts[0])
}

fn get_creds_wifi_16800(line: &str) -> String {
    let cred_string = line
        .split("*")
        .last()
        .expect("Failed to split on '*'");

    let parts = cred_string
        .split(":")
        .map(|s| s.to_owned())
        .collect::<Vec<_>>();

    let ssid = from_hex(&parts[0]).expect("Failed to convert from hex");
    let password = &parts[1];

    format!("{}:{}", ssid, password)
}

fn from_hex(s : &str) -> Result<String, Box<hex::FromHexError>> {
    match hex::FromHex::from_hex(s) {
        Ok(raw) => {
            Ok(String::from_utf8(raw).expect("Failed to convert from hex"))
        },
        Err(e) => Err(Box::new(e))
    }
}

fn main() {
    println!("wifi-cap-parser");

    let matches = App::new("wifi-cap-parser")
        .setting(AppSettings::ArgRequiredElseHelp)
        .version("1.0")
        .author("Gavyn Riebau <gavyn.riebau@gmail.com>")
        .about("Utility functions to parsing wifi packet captures")
        .subcommand(SubCommand::with_name("merge")
            .about("Merges all .pcap files in the current directory and writes to /tmp/all.pcap"))
        .subcommand(SubCommand::with_name("potfile")
            .about("Parses potfile and writes to \"networks.txt\" lines with the format \"<SSID>:<Password>\""))
        .get_matches();

    match matches.subcommand_name() {
        Some(name) => {
            match name.as_ref() {
                "merge" => merge(),
                "potfile" => potfile(),
                _ => {
                    println!("Unrecognized command, quitting");
                    exit(-1);
                }
            }
        },
        None => {
            println!("No command specified, quitting");
            exit(0);
        }
    }   
}
