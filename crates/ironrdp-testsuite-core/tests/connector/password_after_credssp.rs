use ironrdp_connector::{ClientConnector, ClientConnectorState, Credentials, Sequence as _};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::mcs::SendDataRequest;
use ironrdp_pdu::nego::{ConnectionConfirm, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::ClientInfoPdu;
use ironrdp_pdu::rdp::client_info::ClientInfoFlags;
use ironrdp_pdu::x224::X224;

const PASSWORD: &str = "secret-sentinel";

fn connector() -> ClientConnector {
    let mut config = super::test_config();
    config.enable_credssp = true;
    config.autologon = true;
    config.credentials = Credentials::UsernamePassword {
        username: "test".into(),
        password: PASSWORD.into(),
    };
    ClientConnector::new(config, "127.0.0.1:3389".parse().unwrap())
}

/// Negotiates `protocol` as the server's selection and completes the TLS upgrade.
fn negotiate(mut connector: ClientConnector, protocol: SecurityProtocol) -> ClientConnector {
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let confirm = encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol,
    }))
    .unwrap();
    connector.step(&confirm, None, &mut output).unwrap();
    connector.mark_security_upgrade_as_done();
    connector
}

fn step_client_info(mut connector: ClientConnector) -> (ClientInfoPdu, Vec<u8>) {
    connector.state = ClientConnectorState::SecureSettingsExchange {
        io_channel_id: 1003,
        user_channel_id: 1002,
    };
    let mut output = WriteBuf::new();
    connector.step_no_input(&mut output).unwrap();
    let data = decode::<X224<SendDataRequest<'_>>>(output.filled()).unwrap().0;
    let bytes = data.user_data.into_owned();
    let pdu = decode::<ClientInfoPdu>(&bytes).unwrap();
    (pdu, bytes)
}

// oracle: mutant (the configured password reaching the Client Info PDU after CredSSP despite the opt-in)
#[test]
fn client_info_omits_password_after_credssp_when_requested() {
    let mut connector = negotiate(
        connector().with_password_omitted_after_credssp(),
        SecurityProtocol::HYBRID_EX,
    );
    connector.mark_credssp_as_done();
    let (info, encoded) = step_client_info(connector);
    assert!(info.client_info.credentials.password.is_empty());
    let utf16: Vec<u8> = PASSWORD.encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert!(!encoded.windows(utf16.len()).any(|window| window == utf16));
}

// oracle: mutant (omitting the password after CredSSP without the opt-in)
#[test]
fn client_info_keeps_password_after_credssp_by_default() {
    let mut connector = negotiate(connector(), SecurityProtocol::HYBRID_EX);
    connector.mark_credssp_as_done();
    let (info, _) = step_client_info(connector);
    assert_eq!(info.client_info.credentials.password, PASSWORD);
}

// oracle: spec MS-RDPBCGR §2.2.1.11.1.1 (INFO_AUTOLOGON logs on with the included password)
#[test]
fn client_info_keeps_password_without_credssp_when_requested() {
    let connector = negotiate(connector().with_password_omitted_after_credssp(), SecurityProtocol::SSL);
    assert!(!connector.should_perform_credssp());
    let (info, _) = step_client_info(connector);
    assert!(info.client_info.flags.contains(ClientInfoFlags::AUTOLOGON));
    assert_eq!(info.client_info.credentials.password, PASSWORD);
}
