use super::{TelnetMessage, Command, Negotiation, bytes};

/// The result of injecting a byte into a Decoder State
struct DecoderResult {
    /// The new state to move to as a result of this byte
    new_state: TelnetDecoderState,
    /// The message that was produced, if any
    message: Option<TelnetMessage>
}

impl DecoderResult {
    fn new_state(state: TelnetDecoderState) -> DecoderResult {
        DecoderResult { new_state: state, message: Option::None }
    }

    fn new_message(message: TelnetMessage) -> DecoderResult {
        DecoderResult { new_state: TelnetDecoderState::None, message: Option::Some(message) }
    }
}
/// Enumeration of the possible states that the Telnet Decoder can be in
enum TelnetDecoderState {
    /// No special state
    None,
    /// We've just decoded a bare IAC
    Iac,
    // We're just about to negotiate an option state
    Negotiation(Negotiation)
}

/// Mechanism by which we can consume bytes that represent a Telnet byte stream and emit
/// the various Telnet messages that these bytes represent
pub struct TelnetDecoder {
    state: TelnetDecoderState
}

impl TelnetDecoder {
    /// Create a new Telnet Decoder, starting out in no state at all
    pub fn new() -> TelnetDecoder {
        TelnetDecoder {
            state: TelnetDecoderState::None
        }
    }

    /// Inject a byte into the decoder, and if this results in a message being decoded then
    /// return the message that was returned
    ///
    /// # Parameters
    /// * b - The byte to inject
    ///
    /// # Returns
    /// An Option that is Some() if a telnet message has just been decoded, and None if there
    /// are still more bytes required
    ///
    /// # Examples
    /// ```
    /// # use libelinvar::net::telnet::*;
    /// # let mut decoder = TelnetDecoder::new();
    /// decoder.inject_byte(255); // IAC - needs more bytes, so returns None
    /// decoder.inject_byte(253); // DO - needs more bytes, so returns None
    /// decoder.inject_byte(31); // This returns Some(TelnetMessage::NegotiationMessage(Negotiation::Do, 31))
    /// ```
    pub fn inject_byte(&mut self, b: u8) -> Option<TelnetMessage> {
        let result = match self.state {
            TelnetDecoderState::None => decode_from_none(b),
            TelnetDecoderState::Iac => decode_from_iac(b),
            TelnetDecoderState::Negotiation(ref negotiation) => decode_from_negotiation(negotiation.clone(), b)
        };

        self.state = result.new_state;
        result.message
    }
}

fn decode_from_none(b: u8) -> DecoderResult {
    match b {
        bytes::IAC => DecoderResult::new_state(TelnetDecoderState::Iac),
        _ => DecoderResult::new_message(TelnetMessage::Byte(b))
    }
}

fn decode_from_iac(b: u8) -> DecoderResult {
    match b {
        bytes::DATA_MARK => DecoderResult::new_message(TelnetMessage::Command(Command::DataMark)),
        bytes::BREAK => DecoderResult::new_message(TelnetMessage::Command(Command::Break)),
        bytes::INTERRUPT_PROCESS => DecoderResult::new_message(TelnetMessage::Command(Command::InterruptProcess)),
        bytes::ABORT_OUTPUT => DecoderResult::new_message(TelnetMessage::Command(Command::AbortOutput)),
        bytes::ARE_YOU_THERE => DecoderResult::new_message(TelnetMessage::Command(Command::AreYouThere)),
        bytes::ERASE_CHARACTER => DecoderResult::new_message(TelnetMessage::Command(Command::EraseCharacter)),
        bytes::ERASE_LINE => DecoderResult::new_message(TelnetMessage::Command(Command::EraseLine)),
        bytes::GO_AHEAD => DecoderResult::new_message(TelnetMessage::Command(Command::GoAhead)),
        bytes::DO => DecoderResult::new_state(TelnetDecoderState::Negotiation(Negotiation::Do)),
        bytes::DONT => DecoderResult::new_state(TelnetDecoderState::Negotiation(Negotiation::Dont)),
        bytes::WILL => DecoderResult::new_state(TelnetDecoderState::Negotiation(Negotiation::Will)),
        bytes::WONT => DecoderResult::new_state(TelnetDecoderState::Negotiation(Negotiation::Wont)),
        _ => DecoderResult::new_message(TelnetMessage::Byte(b))
    }
}

fn decode_from_negotiation(negotiation: Negotiation, option: u8) -> DecoderResult {
    DecoderResult::new_message(TelnetMessage::Negotiation(negotiation, option))
}

#[cfg(test)]
mod test {
    use super::super::*;

    /// Attempt to decode a list of bytes into a list of Telnet messages
    /// Any bytes that don't decode into a message will not cause an entry to be added to the result
    fn decode_bytes(bytes: Vec<u8>) -> Vec<TelnetMessage> {
        let mut result = Vec::new();
        let mut decoder = TelnetDecoder::new();
        for b in bytes {
            let message = decoder.inject_byte(b);
            if message.is_some() {
                result.push(message.unwrap());
            }
        }

        result
    }

    #[test]
    fn test_decode_simple_byte() {
        let actual = decode_bytes(vec!(200));
        assert_eq!(vec!(TelnetMessage::Byte(200)), actual);
    }

    #[test]
    fn test_decode_iac_byte() {
        let actual = decode_bytes(vec!(255));
        assert_eq!(0, actual.len());
    }

    #[test]
    fn test_decode_escaped_iac_byte() {
        let actual = decode_bytes(vec!(255, 255));
        assert_eq!(vec!(TelnetMessage::Byte(255)), actual);
    }

    #[test]
    fn test_decode_go_ahead() {
        let actual = decode_bytes(vec!(255, 249));
        assert_eq!(vec!(TelnetMessage::Command(Command::GoAhead)), actual);
    }

    #[test]
    fn test_decode_do() {
        let actual = decode_bytes(vec!(255, 253));
        assert_eq!(0, actual.len());
    }

    #[test]
    fn test_decode_do_option() {
        let actual = decode_bytes(vec!(255, 253, 12));
        assert_eq!(vec!(TelnetMessage::Negotiation(Negotiation::Do, 12)), actual);
    }
}
