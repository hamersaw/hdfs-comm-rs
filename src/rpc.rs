use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use comm::StreamHandler;
use prost::{self, Message};

use crate::protos::common::{IpcConnectionContextProto, RequestHeaderProto, RpcRequestHeaderProto, RpcResponseHeaderProto, RpcSaslProto};

use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::RwLock;

static CONNECTION_HEADER: [u8; 7] = [b'h', b'r', b'p', b'c', 9, 0, 0];

pub trait Protocol: Send + Sync {
    fn process(&self, user: &Option<String>, method: &str,
        req_buf: &[u8], resp_buf: &mut Vec<u8>) -> std::io::Result<()>;
}

pub struct Protocols {
    map: RwLock<HashMap<String, Box<dyn Protocol>>>,
}

impl Default for Protocols {
    fn default() -> Self {
        Protocols {
            map: RwLock::new(HashMap::new()),
        }
    }
}

impl Protocols {
    pub fn register(&mut self, protocol_name: &str,
            protocol: Box<dyn Protocol>) {
        let mut map = self.map.write().unwrap();
        map.insert(protocol_name.to_owned(), protocol);
        debug!("registered protocol: {}", protocol_name);
    }
}

impl StreamHandler for Protocols {
    fn process(&self, stream: &mut TcpStream)
            -> Result<(), Box<dyn Error>> {
        // read in connection header - TODO validate
        let mut connection_header = vec![0u8; 7];
        stream.read_exact(&mut connection_header)?;

        let mut user = None;

        // iterate over rpc requests
        loop {
            // read packet
            let packet_length = 
                stream.read_u32::<BigEndian>()? as usize;
            let mut req_buf = vec![0u8; packet_length];
            stream.read_exact(&mut req_buf)?;
            let mut req_buf_index = 0;

            // read RpcRequestHeaderProto
            trace!("parsing RpcRequestHeaderProto: {}", req_buf_index);
            let rpc_header_request = RpcRequestHeaderProto
                ::decode_length_delimited(&req_buf[req_buf_index..])?;
            req_buf_index +=
                calculate_length(rpc_header_request.encoded_len());

            // create RpcResponseHeaderProto
            let mut rpc_header_response =
                RpcResponseHeaderProto::default();
            rpc_header_response.call_id =
                rpc_header_request.call_id as u32;
            rpc_header_response.status = 0; // set to success
            rpc_header_response.client_id =
                Some(rpc_header_request.client_id);

            //rpc_header_response.encode_length_delimited(&mut resp_buf)?;
            let mut resp_buf = Vec::new();

            // match call id of request
            match rpc_header_request.call_id {
                -33 => {
                    trace!("RpcSaslProto: {}", req_buf_index);
                    // parse RpcSaslProto
                    let rpc_sasl = RpcSaslProto
                        ::decode_length_delimited(&req_buf)?;
                    req_buf_index +=
                        calculate_length(rpc_sasl.encoded_len());

                    match rpc_sasl.state {
                        1 =>  {
                            // handle negotiate
                            let mut resp = RpcSaslProto::default();
                            resp.state = 0;

                            resp.encode_length_delimited(&mut resp_buf)?;
                        },
                        _ => unimplemented!(),
                    }
                },
                -3 => {
                    trace!("IpcConnectionContextProto: {}", req_buf_index);
                    // parse IpcConnectionContextProto
                    let ipc_connection_context = IpcConnectionContextProto
                        ::decode_length_delimited(&req_buf[req_buf_index..])?;
                    req_buf_index += calculate_length(
                        ipc_connection_context.encoded_len());

                    if let Some(user_information_proto) =
                            ipc_connection_context.user_info {
                        user = user_information_proto.effective_user;
                    }
                    continue; // don't send response here
                },
                call_id if call_id >= 0 => {
                    trace!("RequestHeaderProto: {}", req_buf_index);
                    let protocols = self.map.read().unwrap();

                    // parse RequestHeaderProto
                    let request_header = RequestHeaderProto
                        ::decode_length_delimited(&req_buf[req_buf_index..])?;
                    req_buf_index +=
                        calculate_length(request_header.encoded_len());

                    // get protocol
                    let protocol_result = protocols.get(&request_header
                        .declaring_class_protocol_name);
                    if protocol_result.is_none() {
                        error!("protocol '{}' does not exist",
                            &request_header.declaring_class_protocol_name);
                    }

                    let protocol = protocol_result.unwrap();

                    // execute method
                    if let Err(e) = protocol.process(&user, 
                            &request_header.method_name,
                            &req_buf[req_buf_index..], &mut resp_buf) {
                        // if error -> set response to failure 
                        rpc_header_response.status = 1;
                        rpc_header_response.error_msg =
                            Some(e.to_string());
                    }
                    // TODO - increment req_buf_index?
                    //  will need to figure out how much data is read
                },
                _ => unimplemented!(),
            }

            // write response buffer
            let mut header_resp_buf = Vec::new();
            rpc_header_response.encode_length_delimited(&mut header_resp_buf)?;

            let resp_len = header_resp_buf.len() + resp_buf.len();
            trace!("writing resp {}", resp_len);
            stream.write_i32::<BigEndian>(resp_len as i32)?;
            stream.write_all(&header_resp_buf)?;
            stream.write_all(&resp_buf)?;

            // check rpc_header_request.rpc_op (2 -> close)
            if rpc_header_request.rpc_op.is_none() || 
                    rpc_header_request.rpc_op.unwrap() == 2 {
                break;
            }
        }

        Ok(())
    }
}

pub struct Client {
    stream: TcpStream,
}

impl Client {
    pub fn new(ip_address: &str, port: u16) -> std::io::Result<Client> {
        // open TcpStream
        let mut stream = TcpStream::connect(
            &format!("{}:{}", ip_address, port))?;

        // write connection header
        stream.write_all(&CONNECTION_HEADER)?;

        Ok(
            Client {
                stream,
            }
        )
    }

    pub fn write_message(&mut self, protocol: &str, 
            method: &str, message: impl Message) 
            -> std::io::Result<(RpcResponseHeaderProto, Vec<u8>)> {
        let mut req_buf = Vec::new();

        // create RpcRequestHeaderProto
        let mut rrh_proto = RpcRequestHeaderProto::default();
        rrh_proto.call_id = 0; // TODO - monotonically increasing number
        rrh_proto.encode_length_delimited(&mut req_buf)?;

        // create RpcHeaderProto
        let mut rh_proto = RequestHeaderProto::default();
        rh_proto.declaring_class_protocol_name = protocol.to_string();
        rh_proto.method_name = method.to_string();
        rh_proto.encode_length_delimited(&mut req_buf)?;

        // add message onto buf
        message.encode_length_delimited(&mut req_buf)?;
     
        // write to stream
        self.stream.write_i32::<BigEndian>(req_buf.len() as i32)?;
        self.stream.write_all(&req_buf)?;
        self.stream.flush()?;

        // read response
        let packet_length =
            self.stream.read_u32::<BigEndian>()? as usize;
        let mut resp_buf = vec![0u8; packet_length];
        self.stream.read_exact(&mut resp_buf)?;

        // handle response
        let rrph_proto = RpcResponseHeaderProto
            ::decode_length_delimited(&resp_buf[0..])?;

        for _ in 0..calculate_length(rrph_proto.encoded_len()) {
            resp_buf.remove(0);
        }

        Ok((rrph_proto, resp_buf))
    }
}

fn calculate_length(length: usize) -> usize {
    length + prost::encoding::encoded_len_varint(length as u64)
}

#[cfg(test)]
mod tests {
    use super::{Client, Protocol, Protocols};
    use crate::protos::hdfs::DatanodeLocalInfoProto;

    use comm::Server;
    use prost::Message;

    use std::net::TcpListener;
    use std::sync::Arc;

    struct NullProtocol {
    }

    impl Protocol for NullProtocol {
        fn process(&self, _user: &Option<String>, method: &str,
                req_buf: &[u8], resp_buf: &mut Vec<u8>) -> std::io::Result<()> {
            match method {
                "test" => self.test(req_buf, resp_buf)?,
                _ => error!("unimplemented method '{}'", method),
            }

            Ok(())
        }
    }

    impl NullProtocol {
        fn test(&self, req_buf: &[u8],
                resp_buf: &mut Vec<u8>) -> std::io::Result<()> {
            let request = DatanodeLocalInfoProto
                ::decode_length_delimited(req_buf)?;
            request.encode_length_delimited(resp_buf)?;

            Ok(())
        }
    }

    #[test]
    fn protocol() {
        let ip_address = "127.0.0.1";
        let port = 19001;
        let protocol = "test.example";

        // register protocols
        let mut protocols = Protocols::default();
        protocols.register(&protocol, Box::new(NullProtocol{ }));

        // initialize Server
        let listener = TcpListener::bind(&format!("{}:{}",
            &ip_address, port)).expect("bind listener");

        let handler = Arc::new(protocols);
        let mut server = Server::new(listener, 50, handler);
     
        // start server
        server.start_threadpool(2).expect("start server");

        // connect client and send requests
        {
            let mut client = Client::new(&ip_address, port)
                .expect("initialize client");

            // send valid message
            let request = DatanodeLocalInfoProto::default();
            let (_, resp_buf) = client.write_message(&protocol, 
                "test", request).expect("client write valid message");

            let _ = DatanodeLocalInfoProto
                ::decode_length_delimited(resp_buf)
                    .expect("decode response");

            // send invalid message protocol
            let request = DatanodeLocalInfoProto::default();
            let result = client.write_message(
                "invalid.protocol", "test", request);

            assert!(result.is_err());

            // send invalid message method
            let request = DatanodeLocalInfoProto::default();
            let result = client.write_message(
                "&protocol", "invalid_method", request);

            assert!(result.is_err());
        }

        // stop server
        server.stop().expect("stop server");
    }
}
