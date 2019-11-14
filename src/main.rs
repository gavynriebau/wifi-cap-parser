
extern crate glob;
extern crate pcap_file;

use std::fs::File;
use pcap_file::{PcapReader, PcapWriter, PcapHeader, DataLink};
use pcap_file::errors::Error;
use glob::glob;
use std::path::PathBuf;

fn merge_file(path: PathBuf, pcap_writer: &mut PcapWriter<File>) -> Result<(), Error> {
    let file_in = File::open(path)?;
    let pcap_reader = PcapReader::new(file_in)?;

    for pcap in pcap_reader {
        let pcap = pcap?;
        pcap_writer.write_packet(&pcap)?;
    }

    Ok(())
}

fn main() {
    println!("wifi-cap-parser");

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
}
