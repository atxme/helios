use orion_engine::client::{connect, EngineClient};
use orion_engine::session::{accept_hello, SessionToken};
use orion_engine::{
    limits, read_frame, write_frame, ClientFrame, EngineCommand, EngineFrame, EngineReply,
};
use std::time::Duration;
use tokio::io::{BufReader, DuplexStream, ReadHalf, WriteHalf};

pub(super) struct ScriptedEngine {
    reader: BufReader<ReadHalf<DuplexStream>>,
    writer: WriteHalf<DuplexStream>,
}

/// Opens an authenticated, framed engine session without starting a process.
pub(super) async fn scripted_engine() -> (EngineClient, ScriptedEngine) {
    let token = SessionToken::parse(&"a".repeat(64)).expect("fixture session token");
    let (ui, engine) = tokio::io::duplex(8192);
    let (client, _events) = connect(ui, &token).await.expect("start IPC client");
    let (reader, writer) = tokio::io::split(engine);
    let mut reader = BufReader::new(reader);
    accept_hello(&mut reader, &token)
        .await
        .expect("client hello");
    (client, ScriptedEngine { reader, writer })
}

impl ScriptedEngine {
    pub(super) async fn reply(
        &mut self,
        respond: impl FnOnce(EngineCommand) -> Result<EngineReply, String>,
    ) {
        let frame = tokio::time::timeout(
            Duration::from_secs(3),
            read_frame::<_, ClientFrame>(&mut self.reader, limits::REQUEST_BYTES),
        )
        .await
        .expect("command arrives within test deadline")
        .expect("read command")
        .expect("client still connected");
        let ClientFrame::Request { id, command } = frame else {
            panic!("expected a command after the initial hello");
        };
        let result = respond(*command);
        write_frame(
            &mut self.writer,
            &EngineFrame::Reply {
                id,
                result: result.map(Box::new),
            },
            limits::REPLY_BYTES,
        )
        .await
        .expect("send reply");
    }
}
