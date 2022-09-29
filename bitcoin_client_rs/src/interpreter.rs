use core::fmt::Debug;

use crate::error::BitcoinClientError;

/// Interpreter for the client-side commands.
/// This struct keeps has methods to keep track of:
///   - known preimages
///   - known Merkle trees from lists of elements
/// Moreover, it containes the state that is relevant for the interpreted client side commands:
///   - a queue of bytes that contains any bytes that could not fit in a response from the
///     GET_PREIMAGE client command (when a preimage is too long to fit in a single message) or the
///     GET_MERKLE_LEAF_PROOF command (which returns a Merkle proof, which might be too long to fit
///     in a single message). The data in the queue is returned in one (or more) successive
///     GET_MORE_ELEMENTS commands from the hardware wallet.
/// Finally, it keeps track of the yielded values (that is, the values sent from the hardware
/// wallet with a YIELD client command).
pub struct ClientCommandInterpreter {
    yielded: Vec<Vec<u8>>,
}

impl ClientCommandInterpreter {
    pub fn new() -> Self {
        Self {
            yielded: Vec::new(),
        }
    }
    pub fn execute<T: Debug>(
        &mut self,
        command: Vec<u8>,
    ) -> Result<Vec<u8>, BitcoinClientError<T>> {
        self.yielded.push(command);
        Ok(Vec::new())
    }
}
