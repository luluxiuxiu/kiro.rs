mod debug;
mod test;

mod kiro {
    pub mod machine_id;
    pub mod parser;
    pub mod provider;
    pub mod token_manager;
    pub mod model {
        pub mod credentials;
        pub mod events;
        pub mod token_refresh;
    }
}
mod model {
    pub mod config;
}

use futures::StreamExt;

#[tokio::main]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt::init();

    if let Err(e) = test::call_stream_api().await {
        eprintln!("错误: {}", e);
        std::process::exit(1);
    }
}
