use clap::Parser;
use wez_mdns::{QueryParameters, Result};

#[derive(Debug, Parser)]
struct Opt {
    service_name: String,
}

fn main() -> Result<()> {
    let opt = Opt::parse();

    let params = if opt.service_name.starts_with('_') {
        QueryParameters::SERVICE_LOOKUP
    } else {
        QueryParameters::HOST_LOOKUP
    };
    println!("QueryParameters: {:?}", params);

    smol::block_on(async {
        let responses = wez_mdns::resolve(opt.service_name, params).await?;
        loop {
            let d = responses.recv().await?;
            println!("response: {:#?}", d);
            println!("hosts: {:#?}", d.hosts());
        }
    })
}
