// todo:
// cleanup error handling

pub use std::{env, net::SocketAddr};
use axum::extract::DefaultBodyLimit;
pub use tokio::signal;
pub use socket2::{Socket, Domain, Type, Protocol};

// #[tokio::main]
// #[tokio::main(flavor = "current_thread")]
#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() -> anyhow::Result<()> {
    primal_blossom_server::main_1(my_main).await
}

use primal_blossom_server::{
    log,
    get,
    put,
    options,
    welcome_page_handler,
    options_handler,
    head_handler,
    get_handler,
    put_handler,
    delete_handler,
    Extension,
    Router,
    Config,
    State,
};

async fn shutdown_signal() {
    let mut usr1 = signal::unix::signal(signal::unix::SignalKind::user_defined1()).unwrap();
    tokio::select! {
        _ = signal::ctrl_c() => {},
        _ = usr1.recv() => {},
    }
    log!("signal received, shutting down");
}

use primal_blossom_server::SubscriberExt;
use primal_blossom_server::SubscriberInitExt;

async fn my_main(config: Config, state: State) -> anyhow::Result<()> {
    dbg!(&config);
    dbg!(&state);
    #[cfg(feature = "media-processing")]
    {
        println!("media-processing feature is enabled");
    }

    let port = config.port;
    let cache = state.cache.clone();

    // tracing_subscriber::registry()
    //     // .with(EnvFilter::from_default_env())  // e.g. set RUST_LOG=info in your env
    //     .with(tracing_subscriber::EnvFilter::new("debug"))
    //     .with(tracing_subscriber::fmt::layer().with_ansi(false))
    //     .init();

    let app = Router::new()
        .route("/", get(welcome_page_handler))
        .route("/:path", options(options_handler).head(head_handler).get(get_handler).delete(delete_handler))
        .route("/:path", put(put_handler).layer(DefaultBodyLimit::max(10*1024*1024*1024)))
        .layer(Extension(config))
        .layer(Extension(state))
        // .layer(TraceLayer::new_for_http()
        //     .make_span_with(DefaultMakeSpan::new().include_headers(true))
        //     .on_response(DefaultOnResponse::new().include_headers(true)))
        ;

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    log!("listening on http://{addr}");

    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let std_listener: std::net::TcpListener = socket.into();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            log!("cache size before clear: {}", cache.len());
            cache.clear();
            // log!("cache cleared");
        }
    });

    axum::Server::from_tcp(std_listener).unwrap()
        .serve(app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    log!("server has shut down gracefully");
    Ok(())
}

