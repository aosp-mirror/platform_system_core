use trusty::{TipcChannel, DEFAULT_DEVICE};

const ECHO_NAME: &str = "com.android.ipc-unittest.srv.echo";

#[test]
fn echo() {
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    // Send a message to the echo TA.
    let send_buf = [7u8; 32];
    connection.send(send_buf.as_slice()).unwrap();

    // Receive the response message from the TA.
    let mut recv_buf = [0u8; 32];
    let read_len = connection.recv(&mut recv_buf).expect("Failed to read from connection");

    assert_eq!(
        send_buf.len(),
        read_len,
        "Received data was wrong size (expected {} bytes, received {})",
        send_buf.len(),
        read_len,
    );
    assert_eq!(send_buf, recv_buf, "Received data does not match sent data");
}
