use smoltcp::{
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    time::Instant,
};
use tokio::sync::mpsc::{unbounded_channel, Permit, Sender, UnboundedReceiver, UnboundedSender};

use crate::packet::AnyIpPktFrame;

pub(super) struct VirtualDevice {
    in_buf: UnboundedReceiver<Vec<u8>>,
    pending_in_buf: Option<Vec<u8>>,
    out_buf: Sender<AnyIpPktFrame>,
    mtu: usize,
}

impl VirtualDevice {
    pub(super) fn new(
        iface_egress_tx: Sender<AnyIpPktFrame>,
        mtu: usize,
    ) -> (Self, UnboundedSender<Vec<u8>>) {
        let (iface_ingress_tx, iface_ingress_rx) = unbounded_channel();
        (
            Self {
                in_buf: iface_ingress_rx,
                pending_in_buf: None,
                out_buf: iface_egress_tx,
                mtu,
            },
            iface_ingress_tx,
        )
    }

    pub(super) fn has_pending_ingress(&self) -> bool {
        self.pending_in_buf.is_some() || !self.in_buf.is_empty()
    }

    pub(super) fn egress_capacity(&self) -> usize {
        self.out_buf.capacity()
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buffer = match self.pending_in_buf.take() {
            Some(buffer) => buffer,
            None => self.in_buf.try_recv().ok()?,
        };

        let permit = match self.out_buf.try_reserve() {
            Ok(permit) => permit,
            Err(_) => {
                // Hold on to the ingress packet and retry later instead of dropping it.
                self.pending_in_buf = Some(buffer);
                return None;
            }
        };

        Some((Self::RxToken { buffer }, Self::TxToken { permit }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        match self.out_buf.try_reserve() {
            Ok(permit) => Some(Self::TxToken { permit }),
            Err(_) => None,
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }
}

pub(super) struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer[..])
    }
}

pub(super) struct VirtualTxToken<'a> {
    permit: Permit<'a, Vec<u8>>,
}

impl<'a> TxToken for VirtualTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        self.permit.send(buffer);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn receive_keeps_ingress_packet_when_egress_is_full() {
        let (stack_tx, mut stack_rx) = tokio::sync::mpsc::channel(1);
        stack_tx.send(vec![9, 9, 9]).await.unwrap();

        let (mut device, iface_ingress_tx) = VirtualDevice::new(stack_tx, 1504);
        iface_ingress_tx.send(vec![1, 2, 3]).unwrap();

        assert!(device.has_pending_ingress());
        assert!(device.receive(Instant::ZERO).is_none());
        assert!(device.has_pending_ingress());

        assert_eq!(stack_rx.recv().await.unwrap(), vec![9, 9, 9]);

        let (rx_token, tx_token) = device.receive(Instant::ZERO).expect("pending packet");
        let mut rx_buf = Vec::new();
        rx_token.consume(|buffer| rx_buf.extend_from_slice(buffer));
        assert_eq!(rx_buf, vec![1, 2, 3]);

        tx_token.consume(2, |buffer| buffer.copy_from_slice(&[4, 5]));
        assert_eq!(stack_rx.recv().await.unwrap(), vec![4, 5]);
        assert!(!device.has_pending_ingress());
    }

    #[test]
    fn capabilities_report_configured_mtu() {
        let (stack_tx, _stack_rx) = tokio::sync::mpsc::channel(1);
        let (device, _iface_ingress_tx) = VirtualDevice::new(stack_tx, 1380);
        assert_eq!(device.capabilities().max_transmission_unit, 1380);
    }
}
