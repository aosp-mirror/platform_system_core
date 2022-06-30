use trusty::{TipcChannel, DEFAULT_DEVICE};

const ECHO_NAME: &str = "com.android.ipc-unittest.srv.echo";

#[test]
fn recv_no_alloc() {
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    // Send a message to the echo TA.
    let send_buf = [7u8; 32];
    connection.send(send_buf.as_slice()).unwrap();

    // Receive the response message from the TA. The response message will be the
    // same as the message we just sent.
    let mut recv_buf = [0u8; 32];
    let read_len = connection.recv_no_alloc(recv_buf.as_mut_slice()).unwrap();

    assert_eq!(
        send_buf.len(),
        read_len,
        "Received data was wrong size (expected {} bytes, received {})",
        send_buf.len(),
        read_len,
    );
    assert_eq!(send_buf, recv_buf, "Received data does not match sent data");
}

#[test]
fn recv_small_buf() {
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    // Send a long message to the echo service so that we can test receiving a long
    // message.
    let send_buf = [7u8; 2048];
    connection.send(send_buf.as_slice()).unwrap();

    // Attempt to receive the response message with a buffer that is too small to
    // contain the message.
    let mut recv_buf = [0u8; 32];
    let err = connection.recv_no_alloc(recv_buf.as_mut_slice()).unwrap_err();

    assert_eq!(
        Some(libc::EMSGSIZE),
        err.raw_os_error(),
        "Unexpected error err when receiving incoming message: {:?}",
        err,
    );
}

#[test]
fn recv_empty_vec() {
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    // Send a message to the echo TA.
    let send_buf = [7u8; 2048];
    connection.send(send_buf.as_slice()).unwrap();

    // Receive the response message. `recv_buf` is initially empty, and `recv` is
    // responsible for allocating enough space to hold the message.
    let mut recv_buf = Vec::new();
    connection.recv(&mut recv_buf).unwrap();

    assert_eq!(send_buf.as_slice(), recv_buf, "Received data does not match sent data");
}

#[test]
fn recv_vec_existing_capacity() {
    let mut connection = TipcChannel::connect(DEFAULT_DEVICE, ECHO_NAME)
        .expect("Failed to connect to Trusty service");

    // Send a message to the echo TA.
    let send_buf = [7u8; 2048];
    connection.send(send_buf.as_slice()).unwrap();

    // Receive the response message into a buffer that already has enough capacity
    // to hold the message. No additional capacity should be allocated when
    // receiving the message.
    let mut recv_buf = Vec::with_capacity(2048);
    connection.recv(&mut recv_buf).unwrap();

    assert_eq!(send_buf.as_slice(), recv_buf, "Received data does not match sent data");
    assert_eq!(2048, recv_buf.capacity(), "Additional capacity was allocated when not needed");
}
