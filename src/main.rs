
extern crate clap;
extern crate glob;
extern crate pcap_file;
extern crate shellexpand;
extern crate regex;
extern crate hex;


use clap::{App, SubCommand, AppSettings, Arg};
use std::fs::File;
use pcap_file::{PcapReader, PcapWriter, PcapHeader, DataLink};
use pcap_file::errors::Error;
use glob::glob;
use std::path::PathBuf;
use std::process::exit;
use std::io::{BufRead, BufReader, Write, Read};
use regex::Regex;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;



#[derive(Serialize, Deserialize, Debug)]
struct CsvEntry {
    #[serde(rename = "Unix time")]
    unix_time: u64,

    #[serde(rename = "BSSID")]
    bssid: String,

    #[serde(rename = "Signal strength(-dBm)")]
    signal: f32,

    #[serde(rename = "SSID")]
    ssid: String,

    #[serde(rename = "Longitude")]
    lng: String,

    #[serde(rename = "Latitude")]
    lat: String,

    #[serde(rename = "GPS Accuracy")]
    gps: u32,

    #[serde(rename = "AP Capabilities")]
    capabilities: String,

    #[serde(rename = "Channel")]
    channel: Option<u32>,

    #[serde(rename = "Frequency")]
    frequency: Option<i32>
}

#[derive(Serialize, Deserialize, Debug)]
struct CrackedNetwork {
    #[serde(rename = "SSID")]
    ssid: String,
    #[serde(rename = "Longitude")]
    lng: String,
    #[serde(rename = "Latitude")]
    lat: String,
    #[serde(rename = "Password")]
    password: String
}


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

    let mut networks_file = File::create("/tmp/creds.txt").expect("Failed to create /tmp/creds.txt");

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

fn filter(input: &str) {
    println!("Refreshing /tmp/creds.txt");
    potfile();
    println!("Refreshed /tmp/creds.txt");

    let mut creds_file = File::open("/tmp/creds.txt").expect("Failed to open /tmp/creds.txt");
    let mut creds_contents = String::new();
    creds_file.read_to_string(&mut creds_contents).expect("Failed to read /tmp/creds.txt");

    let cracked_ssids = creds_contents
        .lines()
        .map(|l| {
            let parts = l.split(":")
                .collect::<Vec<_>>();

            (String::from(parts[0]), String::from(parts[1]))
        })
        .collect::<HashMap<_, _>>();

    let mut writer = csv::Writer::from_path("/tmp/cracked.csv").expect("Failed to open output file");

    let mut reader = csv::Reader::from_path(input).expect("Failed to open input file");
    for result in reader.deserialize::<CsvEntry>() {
        match result {
            Ok(rec) => {
                println!("Processing record: {}, {}/{}", rec.ssid, rec.lat, rec.lng);
                if cracked_ssids.contains_key(&rec.ssid) {
                    println!("Contains cracked password");
                    let password = &cracked_ssids[&rec.ssid];
                    let cracked_network = CrackedNetwork {
                        ssid: rec.ssid,
                        lng: rec.lng,
                        lat: rec.lat,
                        password: password.clone()
                    };

                    writer.serialize(cracked_network).expect("Failed to write record");
                }
            },
            Err(e) => println!("Error: {}", e)
        }
    }

    println!("Wrote filtered network to '/tmp/cracked.csv'");
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
            .about("Parses potfile and writes to \"/tmp/creds.txt\" lines with the format \"<SSID>:<Password>\""))
        .subcommand(SubCommand::with_name("filter")
            .about("Filters a 'wifiscan-export.csv' file (generated from Wifi Tracker android app) to only those networks whose password has been recovered and writes to /tmp/cracked.csv")
            .arg(Arg::with_name("input")
                .short("i")
                .long("input")
                .value_name("INPUT")
                .help("Input wifiscan-export.csv file")
                .takes_value(true)
                .required(true)))
        .get_matches();

    match matches.subcommand_name() {
        Some(name) => {
            match name.as_ref() {
                "merge" => merge(),
                "potfile" => potfile(),
                "filter" => {
                    let input = matches.subcommand_matches("filter")
                        .expect("Failed to get filter subcommand matcher")
                        .value_of("input")
                        .expect("Failed to get value of input arg");

                    filter(input);
                },
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
